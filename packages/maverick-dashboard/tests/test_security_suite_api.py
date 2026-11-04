"""Security/GRC and defensive-hunter dashboard integration contracts.

The tests keep every durable store under a fresh ``MAVERICK_HOME``. They
exercise the HTTP boundary (including CSRF, RBAC, CAS, and governed approval
binding) rather than duplicating the deterministic core-engine unit tests.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_security_suite(tmp_path, monkeypatch):
    from maverick import audit, config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import api, security_api

    home = tmp_path / "maverick-home"
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """[security_ops]
enable = true

[threat_hunt]
enable = true

[env_hunt]
enable = true
response_execution = false

[env_hunt.connectors.cloudtrail]
enable = true
push_enable = true
pivot_enable = false
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in (
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_DASHBOARD_INVITES",
        "MAVERICK_TENANT",
        "MAVERICK_TENANT_BY_USER",
        "MAVERICK_APPROVER_KEYS",
        "MAVERICK_APPROVER_KEYS_DIR",
        "MAVERICK_REQUIRE_SIGNED_APPROVAL",
    ):
        monkeypatch.delenv(name, raising=False)

    # Core mutations must be auditable, but these endpoint tests do not need to
    # couple themselves to the audit-writer file format. Dedicated audit tests
    # cover that format; accepting here makes proposal creation deterministic.
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()
    security_api._response_executor_registries.clear()
    security_api._environment_connector_transports.clear()
    security_api._environment_enrichment_providers.clear()
    security_api.stop_hunter_scheduler(timeout=0.1)
    from maverick import shield_policy

    monkeypatch.setattr(shield_policy, "shield_available", lambda: True)
    monkeypatch.setattr(shield_policy, "scan_block", lambda _text: None)
    yield {"home": home, "config": config_path}
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()
    security_api._response_executor_registries.clear()
    security_api._environment_connector_transports.clear()
    security_api._environment_enrichment_providers.clear()
    security_api.stop_hunter_scheduler(timeout=0.1)


def _assert_ok(response, expected: int = 200) -> dict:
    assert response.status_code == expected, response.text
    return response.json()


def _create_control() -> dict:
    return _assert_ok(
        client.post(
            "/api/v1/security/controls",
            json={
                "framework": "internal",
                "control_id": "SEC-001",
                "title": "Administrative access review",
                "implementation_status": "not_started",
                "owner": "security-owner",
                "applicability_rationale": "Privileged identities are in scope.",
                "crosswalk": ["soc2:CC6.2", "iso27001:A.5.18"],
            },
        ),
        201,
    )


def _create_approved_evidence(control_id: str) -> dict:
    evidence = _assert_ok(
        client.post(
            "/api/v1/security/evidence",
            json={
                "title": "Reviewed security artifact",
                "text": (
                    "SEC-001 requires administrative identities to use MFA and "
                    "undergo a quarterly access review."
                ),
                "source": "test-fixture",
                "control_ids": [control_id],
            },
        ),
        201,
    )
    return _assert_ok(
        client.post(
            f"/api/v1/security/evidence/{evidence['id']}/decision",
            json={
                "decision": "approved",
                "rationale": "Auditor verified the source artifact.",
                "expected_revision": evidence["revision"],
            },
        )
    )


def test_connected_document_evidence_is_scoped_untrusted_and_review_gated(monkeypatch):
    from maverick import doc_discovery

    control = _create_control()
    connector_calls = []
    monkeypatch.setattr(doc_discovery, "enabled", lambda: True)

    def configured_sources(**kwargs):
        connector_calls.append(("configured", kwargs))
        return ["msgraph"]

    def discover(subject, **kwargs):
        connector_calls.append(("discover", {"subject": subject, **kwargs}))
        return [
            doc_discovery.DocHit(
                source="msgraph",
                doc_id="doc-1",
                name="quarterly-access-review.txt",
                ref={"drive_id": "drive-1"},
            )
        ]

    def fetch(source, doc_id, ref=None, **kwargs):
        connector_calls.append(
            ("fetch", {"source": source, "doc_id": doc_id, "ref": ref, **kwargs})
        )
        return (
            b"SEC-001 requires administrative identities to use MFA and "
            b"undergo a quarterly access review.",
            "text/plain",
        )

    monkeypatch.setattr(doc_discovery, "configured_sources", configured_sources)
    monkeypatch.setattr(doc_discovery, "discover", discover)
    monkeypatch.setattr(doc_discovery, "fetch", fetch)

    searched = _assert_ok(
        client.get(
            "/api/v1/security/evidence-documents",
            params={"subject": "administrative access"},
        )
    )
    assert searched["enabled"] is True
    assert searched["hits"][0]["doc_id"] == "doc-1"
    mapped = _assert_ok(
        client.post(
            "/api/v1/security/evidence/from-document",
            json={
                "title": "quarterly-access-review.txt",
                "source": "msgraph",
                "doc_id": "doc-1",
                "ref": {"drive_id": "drive-1"},
                "control_ids": ["SEC-001"],
            },
        ),
        201,
    )
    assert mapped["status"] == "pending_review"
    assert mapped["extraction_confidence"] == "untrusted"
    assert mapped["review_required"] is True
    assert mapped["verdicts"][0]["evidence_quote"]
    assert mapped["document_evidence"]["confidence"] == "untrusted"
    assert mapped["document_evidence"]["review_required"] is True
    assert len(mapped["document_evidence"]["binding_sha256"]) == 64
    assert connector_calls[0] == (
        "configured",
        {"principal": None, "allow_ambient_credentials": True},
    )
    assert connector_calls[-1][1]["max_bytes"] == 16 * 1024 * 1024
    assert connector_calls[-1][1]["allow_ambient_credentials"] is True
    assert control["id"] in {row["control_id"] for row in mapped["verdicts"]}


def test_connected_document_evidence_fails_honestly(monkeypatch):
    from maverick import doc_discovery

    monkeypatch.setattr(doc_discovery, "enabled", lambda: True)
    monkeypatch.setattr(doc_discovery, "configured_sources", lambda **kwargs: [])
    unavailable = _assert_ok(
        client.get(
            "/api/v1/security/evidence-documents",
            params={"subject": "access review"},
        )
    )
    assert unavailable == {"enabled": False, "hits": []}
    assert client.get("/api/v1/security/evidence-documents").status_code == 422

    def failed_fetch(*args, **kwargs):
        raise RuntimeError("connector leaked detail")

    monkeypatch.setattr(doc_discovery, "fetch", failed_fetch)
    failed = client.post(
        "/api/v1/security/evidence/from-document",
        json={"title": "evidence.txt", "source": "msgraph", "doc_id": "doc-1"},
    )
    assert failed.status_code == 502
    assert failed.json() == {"detail": "document source request failed"}
    assert "leaked" not in failed.text


def test_controls_require_nonblank_owner_on_create_update_and_initialize():
    missing = client.post(
        "/api/v1/security/controls",
        json={
            "framework": "internal",
            "control_id": "SEC-MISSING-OWNER",
            "title": "Owner is required",
        },
    )
    assert missing.status_code == 422
    blank = client.post(
        "/api/v1/security/controls",
        json={
            "framework": "internal",
            "control_id": "SEC-BLANK-OWNER",
            "title": "Owner is required",
            "owner": "   ",
        },
    )
    assert blank.status_code == 422
    control = _create_control()
    blank_update = client.patch(
        f"/api/v1/security/controls/{control['id']}",
        json={"owner": "  ", "expected_revision": control["revision"]},
    )
    assert blank_update.status_code == 422
    assert client.post("/api/v1/security/controls/initialize").status_code == 422
    assert client.post(
        "/api/v1/security/controls/initialize", params={"owner": "  "},
    ).status_code == 422
    initialized = _assert_ok(
        client.post(
            "/api/v1/security/controls/initialize", params={"owner": "ciso"},
        ),
        201,
    )
    assert initialized["created"] >= 1
    assert all(row["owner"] == "ciso" for row in initialized["controls"])


def _environment_attack_body(*, marker: str = "RAW-CREDENTIAL-MARKER-7391") -> dict:
    customer_rule = {
        "title": "Customer console-login watch",
        "id": "customer-console-login",
        "logsource": {"product": "aws", "service": "cloudtrail"},
        "detection": {
            "selection": {"action": "ConsoleLogin"},
            "condition": "selection",
        },
        "tags": ["attack.t1078"],
        "level": "high",
    }
    return {
        "connector": "cloudtrail",
        "events": [
            {
                "eventID": "cloud-login-1",
                "eventTime": "2026-07-19T12:00:00Z",
                "eventName": "ConsoleLogin",
                "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
                "additionalEventData": {"MFAUsed": "No"},
                "sourceIPAddress": "203.0.113.8",
                "credential_blob": marker,
            },
            {
                "eventID": "cloud-key-1",
                "eventTime": "2026-07-19T12:01:00Z",
                "eventName": "CreateAccessKey",
                "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
            },
        ],
        "sigma_rules": [json.dumps(customer_rule)],
    }


def _ingest_environment_attack() -> tuple[dict, dict, dict]:
    ingest = _assert_ok(
        client.post("/api/v1/security/soc/ingest", json=_environment_attack_body())
    )
    summary = _assert_ok(client.get("/api/v1/security/soc/summary"))
    investigation = next(
        row for row in summary["investigations"]
        if row.get("response_proposal") and row.get("approval_id")
    )
    proposal = investigation["response_proposal"]
    return ingest, investigation, proposal


def test_security_pages_and_report_render_seeded_program():
    control = _create_control()
    evidence = _create_approved_evidence(control["id"])
    _assert_ok(
        client.post(
            "/api/v1/security/risks",
            json={
                "title": "Privileged credential theft",
                "likelihood": 4,
                "impact": 5,
                "likelihood_rationale": "Privileged identities are routinely targeted.",
                "impact_rationale": "Compromise grants production administrative access.",
                "owner": "ciso",
                "control_ids": [control["id"]],
                "evidence_ids": [evidence["id"]],
            },
        ),
        201,
    )

    page = client.get("/security")
    assert page.status_code == 200, page.text
    assert "Security &amp; GRC" in page.text
    assert "Administrative access review" in page.text
    assert "Privileged credential theft" in page.text
    assert 'href="/security/report"' in page.text

    report = client.get("/security/report")
    assert report.status_code == 200, report.text
    assert "Security &amp; GRC" in report.text
    assert "Print or save as PDF" in report.text

    for route, phrase in (
        ("/security/threats", "Lightwork threat check"),
        ("/security/soc", "Threat monitoring"),
    ):
        response = client.get(route)
        assert response.status_code == 200, response.text
        assert phrase in response.text


def test_security_workspace_reads_plainly_with_pickers_for_people_and_records():
    """Owners, frameworks, controls and evidence are chosen from lists; statuses
    and scores read as words; nothing on the page is developer language."""
    from maverick_dashboard import rbac

    from test_support.plain_language import developer_terms, visible_text

    rbac.set_role("user:jane@example.com", "operator")
    now = time.time()
    control = _create_control()
    evidence = _create_approved_evidence(control["id"])
    _assert_ok(client.post("/api/v1/security/risks", json={
        "title": "Privileged credential theft", "likelihood": 4, "impact": 5,
        "likelihood_rationale": "Targeted.", "impact_rationale": "Admin access.",
        "owner": "user:jane@example.com", "evidence_ids": [evidence["id"]]}), 201)
    _assert_ok(client.post("/api/v1/security/poams", json={
        "finding": "Restrict storage", "owner": "ciso", "due_at": now + 86400}), 201)
    _assert_ok(client.post("/api/v1/security/policies", json={
        "title": "Access policy", "owner": "ciso", "review_cadence_days": 365}), 201)
    _assert_ok(client.post("/api/v1/security/incidents", json={
        "title": "Lost laptop", "severity": "high", "clock_ids": ["gdpr_eu_72h"]}), 201)
    page = client.get("/security").text
    assert developer_terms(page) == []
    text = visible_text(page)
    for label in ("Choose a person", "Someone else…", "Add your own control",
                  "Controls it supports", "Evidence behind it", "Reporting deadlines that might apply",
                  "Send for review", "Retire", "4 – Likely", "5 – Severe", "Fix plans"):
        assert label in text, label
    assert "jane@example.com" in text  # the owner picker lists people by name
    assert "20 of 25 (Critical)" in text  # risk score with its scale
    assert "EU GDPR supervisory-authority notice" in text
    assert "not_started" not in text and "revision" not in text.lower()
    report = client.get("/security/report").text
    assert developer_terms(report) == []
    assert "Download data (for other tools)" in report and "onclick" not in report


def test_control_evidence_human_review_and_revision_cas():
    control = _create_control()
    direct_verdict = client.patch(
        f"/api/v1/security/controls/{control['id']}",
        json={
            "expected_revision": control["revision"],
            "implementation_status": "partial",
        },
    )
    assert direct_verdict.status_code == 422
    updated = _assert_ok(
        client.patch(
            f"/api/v1/security/controls/{control['id']}",
            json={
                "expected_revision": control["revision"],
                "implementation_status": "planned",
            },
        )
    )
    stale = client.patch(
        f"/api/v1/security/controls/{control['id']}",
        json={
            "expected_revision": control["revision"],
            "implementation_status": "not_applicable",
        },
    )
    assert stale.status_code == 409

    evidence = _assert_ok(
        client.post(
            "/api/v1/security/evidence",
            json={
                "title": "Quarterly access review",
                "text": (
                    "SEC-001 requires administrative accounts to be inspected "
                    "quarterly with unique identities and MFA."
                ),
                "source": "test-fixture",
                "control_ids": [control["id"]],
            },
        ),
        201,
    )
    assert evidence["review_required"] is True
    assert evidence["status"] == "pending_review"
    premature = client.post(
        f"/api/v1/security/controls/{control['id']}/evidence",
        json={
            "evidence_id": evidence["id"],
            "implementation_status": "implemented",
            "expected_revision": updated["revision"],
        },
    )
    assert premature.status_code == 422

    approved = _assert_ok(
        client.post(
            f"/api/v1/security/evidence/{evidence['id']}/decision",
            json={
                "decision": "approved",
                "rationale": "Auditor verified the source-system artifact.",
                "expected_revision": evidence["revision"],
            },
        )
    )
    assert approved["decision"]["rationale"] == (
        "Auditor verified the source-system artifact."
    )
    applied = _assert_ok(
        client.post(
            f"/api/v1/security/controls/{control['id']}/evidence",
            json={
                "evidence_id": evidence["id"],
                "implementation_status": "implemented",
                "expected_revision": updated["revision"],
            },
        )
    )
    assert applied["implementation_status"] == "implemented"
    assert applied["evidence_ids"] == [evidence["id"]]
    assert client.get("/api/v1/security/controls/CTL-missing").status_code == 404
    assert client.get("/api/v1/security/evidence/EVD-missing").status_code == 404


def test_risk_poam_policy_and_incident_human_lifecycles():
    now = time.time()
    control = _create_control()
    evidence = _create_approved_evidence(control["id"])
    risk = _assert_ok(
        client.post(
            "/api/v1/security/risks",
            json={
                "title": "Public object storage",
                "likelihood": 5,
                "impact": 5,
                "likelihood_rationale": "The bucket is exposed to anonymous callers.",
                "impact_rationale": "Sensitive customer data could be disclosed.",
                "owner": "ciso",
                "control_ids": [control["id"]],
                "evidence_ids": [evidence["id"]],
            },
        ),
        201,
    )
    treated = _assert_ok(
        client.post(
            f"/api/v1/security/risks/{risk['id']}/treatment",
            json={
                "treatment": "mitigate",
                "plan": "Restrict the bucket and add monitoring.",
                "residual_likelihood": 2,
                "residual_impact": 4,
                "residual_likelihood_rationale": (
                    "Organization policy prevents anonymous access."
                ),
                "residual_impact_rationale": (
                    "Encrypted replicas still require a recovery review."
                ),
                "evidence_ids": [evidence["id"]],
                "owner": "cloud-owner",
                "expected_revision": risk["revision"],
            },
        )
    )
    exception = _assert_ok(
        client.post(
            f"/api/v1/security/risks/{risk['id']}/exception",
            json={
                "owner": "cloud-owner",
                "rationale": "Migration window approved by the CISO.",
                "expires_at": now + 7 * 86400,
                "expected_revision": treated["revision"],
            },
        )
    )
    assert exception["exception"]["rationale"] == (
        "Migration window approved by the CISO."
    )

    poam = _assert_ok(
        client.post(
            "/api/v1/security/poams",
            json={
                "finding": "Restrict public object storage",
                "owner": "cloud-owner",
                "due_at": now + 14 * 86400,
                "milestones": [{"title": "Apply organization policy"}],
            },
        ),
        201,
    )
    in_progress = _assert_ok(
        client.patch(
            f"/api/v1/security/poams/{poam['id']}",
            json={
                "status": "in_progress",
                "note": "Remediation started.",
                "expected_revision": poam["revision"],
            },
        )
    )
    assert in_progress["status"] == "in_progress"

    vendor = _assert_ok(
        client.post(
            "/api/v1/security/vendors",
            json={
                "name": "CloudCo",
                "criticality": "high",
                "owner": "vendor-owner",
                "services": "Production object storage",
                "posture": {
                    "independent_assurance": True,
                    "encryption": True,
                    "mfa": False,
                    "incident_sla": True,
                    "subprocessors": True,
                    "vulnerability_management": True,
                    "business_continuity": True,
                    "data_deletion": True,
                },
            },
        ),
        201,
    )
    assert vendor["status"] == "pending_review"
    assert vendor["review_required"] is True
    vendor_decision = _assert_ok(
        client.post(
            f"/api/v1/security/vendors/{vendor['id']}/decision",
            json={
                "decision": "needs_work",
                "rationale": "Require MFA remediation before approval.",
                "expected_revision": vendor["revision"],
            },
        )
    )
    assert vendor_decision["status"] == "needs_work"

    policy = _assert_ok(
        client.post(
            "/api/v1/security/policies",
            json={"title": "Access policy", "owner": "policy-owner"},
        ),
        201,
    )
    review = _assert_ok(
        client.post(
            f"/api/v1/security/policies/{policy['id']}/transition",
            json={
                "target_status": "review",
                "note": "Ready for review.",
                "expected_revision": policy["revision"],
            },
        )
    )
    approved = _assert_ok(
        client.post(
            f"/api/v1/security/policies/{policy['id']}/transition",
            json={
                "target_status": "approved",
                "note": "CISO approved publication.",
                "expected_revision": review["revision"],
            },
        )
    )
    attested = _assert_ok(
        client.post(
            f"/api/v1/security/policies/{policy['id']}/attest",
            json={
                "subject": "employee:42",
                "statement": "I read and understand this policy.",
                "expected_revision": approved["revision"],
            },
        )
    )
    assert attested["status"] == "attested"

    incident = _assert_ok(
        client.post(
            "/api/v1/security/incidents",
            json={
                "title": "Material service compromise",
                "severity": "high",
                "clock_ids": ["nis2_early_24h"],
                "discovered_at": now,
            },
        ),
        201,
    )
    running = _assert_ok(
        client.post(
            f"/api/v1/security/incidents/{incident['id']}/clock",
            json={
                "clock_id": "nis2_early_24h",
                "anchor_at": now,
                "expected_revision": incident["revision"],
            },
        )
    )
    decided = _assert_ok(
        client.post(
            f"/api/v1/security/incidents/{incident['id']}/notification",
            json={
                "clock_id": "nis2_early_24h",
                "notifiable": True,
                "rationale": "Counsel determined the duty applies.",
                "expected_revision": running["revision"],
            },
        )
    )
    contained = _assert_ok(
        client.post(
            f"/api/v1/security/incidents/{incident['id']}/phase",
            json={
                "phase": "containment",
                "note": "Affected workloads isolated.",
                "expected_revision": decided["revision"],
            },
        )
    )
    eradicated = _assert_ok(
        client.post(
            f"/api/v1/security/incidents/{incident['id']}/phase",
            json={
                "phase": "eradication",
                "note": "Persistence removed and credentials rotated.",
                "expected_revision": contained["revision"],
            },
        )
    )
    recovered = _assert_ok(
        client.post(
            f"/api/v1/security/incidents/{incident['id']}/phase",
            json={
                "phase": "recovery",
                "note": "Service restored from a verified image.",
                "expected_revision": eradicated["revision"],
            },
        )
    )
    closed = _assert_ok(
        client.post(
            f"/api/v1/security/incidents/{incident['id']}/close",
            json={
                "summary": "Recovery validated; follow-up is tracked in POA&M.",
                "expected_revision": recovered["revision"],
            },
        )
    )
    assert closed["status"] == "closed"
    missing = client.post(
        "/api/v1/security/risks/RSK-missing/close",
        json={"rationale": "not present", "expected_revision": 1},
    )
    assert missing.status_code == 404


def test_audit_engagement_nested_records_and_conflicts():
    control = _create_control()
    evidence = _create_approved_evidence(control["id"])
    audit = _assert_ok(
        client.post(
            "/api/v1/security/audits",
            json={
                "name": "SOC 2 readiness",
                "framework": "soc2",
                "scope": "Production platform",
                "owner": "audit-owner",
            },
        ),
        201,
    )
    requested = _assert_ok(
        client.post(
            f"/api/v1/security/audits/{audit['id']}/evidence-requests",
            json={
                "description": "Provide quarterly access-review evidence.",
                "owner": "iam-owner",
                "due_at": time.time() + 30 * 86400,
                "control_ids": [control["id"]],
                "expected_revision": audit["revision"],
            },
        )
    )
    tested = _assert_ok(
        client.post(
            f"/api/v1/security/audits/{audit['id']}/control-tests",
            json={
                "control_id": control["id"],
                "procedure": "Inspect the quarterly access-review sample.",
                "result": "fail",
                "evidence_ids": [evidence["id"]],
                "expected_revision": requested["revision"],
            },
        )
    )
    finding = _assert_ok(
        client.post(
            f"/api/v1/security/audits/{audit['id']}/findings",
            json={
                "title": "Access-review evidence is incomplete",
                "severity": "high",
                "control_ids": [control["id"]],
                "owner": "iam-owner",
                "expected_revision": tested["revision"],
            },
        )
    )
    assert finding["findings"][0]["status"] == "open"
    cannot_complete = client.patch(
        f"/api/v1/security/audits/{audit['id']}/status",
        json={"status": "complete", "expected_revision": finding["revision"]},
    )
    assert cannot_complete.status_code == 422
    stale = client.post(
        f"/api/v1/security/audits/{audit['id']}/control-tests",
        json={
            "control_id": control["id"],
            "procedure": "Inspect another sample.",
            "result": "pass",
            "evidence_ids": [evidence["id"]],
            "expected_revision": audit["revision"],
        },
    )
    assert stale.status_code == 409
    assert client.get("/api/v1/security/audits/AUD-missing").status_code == 404


def test_viewer_aggregates_operator_records_and_global_admin_controls(monkeypatch):
    from maverick_dashboard import auth

    _create_control()
    role = {"value": "viewer"}
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:analyst")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: role["value"])
    monkeypatch.setattr(
        auth, "global_role_for_principal", lambda principal: role["value"]
    )

    for route in (
        "/api/v1/security/summary",
        "/api/v1/security/regulatory-clocks",
        "/api/v1/security/threats/stats",
        "/api/v1/security/soc/stats",
    ):
        assert client.get(route).status_code == 200, route
    viewer_summary = _assert_ok(client.get("/api/v1/security/summary"))
    serialized_gaps = json.dumps(
        viewer_summary["readiness"].get("top_control_gaps", []),
        sort_keys=True,
    )
    assert "security-owner" not in serialized_gaps
    assert "Administrative access review" not in serialized_gaps
    for route in (
        "/api/v1/security/report",
        "/api/v1/security/controls",
        "/api/v1/security/threats/summary",
        "/api/v1/security/soc/summary",
        "/security",
    ):
        assert client.get(route).status_code == 403, route
    assert client.get("/api/v1/security/config").status_code == 403

    role["value"] = "operator"
    assert client.get("/api/v1/security/report").status_code == 200
    assert client.get("/api/v1/security/controls").status_code == 200
    assert client.get("/security").status_code == 200
    assert client.get("/api/v1/security/config").status_code == 403
    denied_execution = client.post(
        "/api/v1/security/soc/responses/execute",
        json={
            "investigation_id": "inv-missing",
            "proposal_id": "response-missing",
            "approval_id": 1,
            "executor": "missing",
            "signature": "0" * 128,
            "expected_revision": 1,
        },
    )
    assert denied_execution.status_code == 403

    role["value"] = "admin"
    assert client.get("/api/v1/security/config").status_code == 200


def test_feature_switch_rejects_tenant_only_admin(monkeypatch):
    from maverick_dashboard import auth, settings_store

    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "admin")
    monkeypatch.setattr(
        auth, "global_role_for_principal", lambda principal: "viewer"
    )

    response = client.post(
        "/api/v1/features/switches",
        json={"section": "threat_hunt", "enabled": False},
    )

    assert response.status_code == 403
    assert settings_store.load_overlay() == {}


def test_hunter_feature_switch_uses_governed_security_update(monkeypatch):
    from maverick_dashboard import security_api

    seen = []

    def current(_request):
        return {
            "security_ops": True, "threat_hunt": False, "env_hunt": True,
            "response_execution": False, "revision": 7,
        }

    async def update(_request, body):
        seen.append(body)
        return {}

    monkeypatch.setattr(security_api, "security_config", current)
    monkeypatch.setattr(security_api, "update_security_config", update)

    response = client.post(
        "/api/v1/features/switches",
        json={"section": "threat_hunt", "enabled": True},
    )

    assert response.status_code == 200
    assert response.json() == {"section": "threat_hunt", "enabled": True}
    assert len(seen) == 1
    assert seen[0].model_dump() == {
        "security_ops": True, "threat_hunt": True, "env_hunt": True,
        "response_execution": False, "expected_revision": 7,
    }


def test_security_config_preserves_unrelated_overlay_fields_and_audits(monkeypatch):
    from maverick import config
    from maverick_dashboard import security_api, settings_store

    config.dashboard_overrides_path().write_text(
        """[features]
savings = true

[providers.openai]
base_url = "http://127.0.0.1:9000/v1"

[security_ops]
enable = true
review_days = 90

[threat_hunt]
enable = false
baseline_days = 30

[env_hunt]
enable = false
response_execution = false
poll_seconds = 73
connector_profile = "vendor-neutral"
connectors = ["cloudtrail", "edr"]

[env_hunt.vendor_extensions]
acme = "profile-a"
""",
        encoding="utf-8",
    )
    config.reset_config_cache()

    recorded = []

    class AcceptingAudit:
        def record(self, event):
            recorded.append(event)
            return True

    monkeypatch.setattr(
        "maverick.audit.global_audit_log", lambda: AcceptingAudit()
    )
    scheduler_calls = []
    monkeypatch.setattr(
        security_api,
        "start_hunter_scheduler",
        lambda: scheduler_calls.append("start") or True,
    )
    current = _assert_ok(client.get("/api/v1/security/config"))
    response = _assert_ok(
        client.put(
            "/api/v1/security/config",
            json={
                "security_ops": False,
                "threat_hunt": True,
                "env_hunt": True,
                "response_execution": False,
                "expected_revision": current["revision"],
            },
        )
    )
    assert response == {
        "security_ops": False,
        "threat_hunt": True,
        "env_hunt": True,
        "response_execution": False,
        "connectors": ["cloudtrail", "edr"],
        "revision": current["revision"] + 1,
    }
    overlay = settings_store.load_overlay()
    assert overlay["features"] == {"savings": True}
    assert overlay["providers"]["openai"]["base_url"] == "http://127.0.0.1:9000/v1"
    assert overlay["security_ops"]["review_days"] == 90
    assert overlay["threat_hunt"]["baseline_days"] == 30
    assert overlay["env_hunt"]["poll_seconds"] == 73
    assert overlay["env_hunt"]["connector_profile"] == "vendor-neutral"
    assert overlay["env_hunt"]["connectors"] == ["cloudtrail", "edr"]
    assert overlay["env_hunt"]["vendor_extensions"] == {"acme": "profile-a"}
    assert overlay["security_suite_control"]["revision"] == current["revision"] + 1
    assert recorded and recorded[0].payload["requested"]["threat_hunt"] is True
    assert recorded[0].payload["actor"] == "local:dashboard"
    assert scheduler_calls == ["start"]
    stale = client.put(
        "/api/v1/security/config",
        json={
            "security_ops": True,
            "threat_hunt": True,
            "env_hunt": True,
            "response_execution": False,
            "expected_revision": current["revision"],
        },
    )
    assert stale.status_code == 409


def test_security_config_rolls_back_exact_overlay_when_audit_refuses(monkeypatch):
    from maverick import config
    from maverick_dashboard import settings_store

    settings_store._write({
        "features": {"savings": True},
        "security_ops": {"enable": True, "review_days": 120},
        "threat_hunt": {"enable": True, "baseline_days": 14},
        "env_hunt": {"enable": True, "response_execution": False},
    })
    overlay_path = config.dashboard_overrides_path()
    before = overlay_path.read_bytes()
    writes = []
    real_write = settings_store._write

    def observed_write(data):
        writes.append(data)
        real_write(data)

    monkeypatch.setattr(settings_store, "_write", observed_write)

    class RefusingAudit:
        def record(self, event):
            return False

    monkeypatch.setattr("maverick.audit.global_audit_log", lambda: RefusingAudit())
    response = client.put(
        "/api/v1/security/config",
        json={
            "security_ops": False,
            "threat_hunt": False,
            "env_hunt": False,
            "response_execution": False,
            "expected_revision": 1,
        },
    )
    assert response.status_code == 503
    assert writes == []
    assert overlay_path.read_bytes() == before
    assert settings_store.load_overlay()["security_ops"]["enable"] is True
    invalid = client.put(
        "/api/v1/security/config",
        json={
            "security_ops": True,
            "threat_hunt": True,
            "env_hunt": False,
            "response_execution": True,
            "expected_revision": 1,
        },
    )
    assert invalid.status_code == 422


def test_security_config_refuses_malformed_overlay_without_replacing_it():
    from maverick import config
    from maverick_dashboard import settings_store

    overlay_path = config.dashboard_overrides_path()
    overlay_path.write_text(
        """[providers.anthropic]
api_key = "must-survive"  # pragma: allowlist secret
this is not valid toml
""",
        encoding="utf-8",
    )
    before = overlay_path.read_bytes()

    with pytest.raises(settings_store.SecuritySuiteConfigUnavailable):
        settings_store.security_suite_revision()
    with pytest.raises(settings_store.SecuritySuiteConfigUnavailable):
        settings_store.set_security_suite(
            security_ops=True,
            threat_hunt=False,
            env_hunt=False,
            response_execution=False,
            actor="test:admin",
            expected_revision=1,
        )
    with pytest.raises(settings_store.SecuritySuiteConfigUnavailable):
        settings_store.set_provider("anthropic", api_key="replacement")  # pragma: allowlist secret
    assert overlay_path.read_bytes() == before


def test_security_config_lifecycle_and_actor_label_are_safe(monkeypatch):
    from maverick_dashboard import api, request_identity, security_api

    recorded = []

    class AcceptingAudit:
        def record(self, event):
            recorded.append(event)
            return True

    monkeypatch.setattr("maverick.audit.global_audit_log", lambda: AcceptingAudit())
    monkeypatch.setattr(api, "_request_actor", lambda _request: "actor-" + "x" * 500)
    monkeypatch.setattr(request_identity, "request_actor", lambda _request: "actor-" + "x" * 500)
    lifecycle = []
    monkeypatch.setattr(
        security_api,
        "start_hunter_scheduler",
        lambda: lifecycle.append("start") or True,
    )
    monkeypatch.setattr(
        security_api,
        "stop_hunter_scheduler",
        lambda **_kwargs: lifecycle.append("stop") or True,
    )
    current = _assert_ok(client.get("/api/v1/security/config"))
    enabled = _assert_ok(
        client.put(
            "/api/v1/security/config",
            json={
                "security_ops": True,
                "threat_hunt": True,
                "env_hunt": False,
                "response_execution": False,
                "expected_revision": current["revision"],
            },
        )
    )
    assert lifecycle == ["start"]
    actor = recorded[-1].payload["actor"]
    assert len(actor) <= 256
    assert "#sha256:" in actor
    assert recorded[-1].payload["phase"] == "authorized"
    _assert_ok(
        client.put(
            "/api/v1/security/config",
            json={
                "security_ops": True,
                "threat_hunt": False,
                "env_hunt": False,
                "response_execution": False,
                "expected_revision": enabled["revision"],
            },
        )
    )
    assert lifecycle == ["start", "stop"]


def test_security_scheduler_reconciles_effective_operator_authority(tmp_path, monkeypatch):
    from maverick import config
    from maverick_dashboard import security_api

    operator = tmp_path / "operator.toml"
    operator.write_text("[threat_hunt]\nenable = true\n", encoding="utf-8")
    monkeypatch.setenv(config.CONFIG_OVERLAY_ENV, str(operator))
    config.reset_config_cache()

    class AcceptingAudit:
        def record(self, _event):
            return True

    monkeypatch.setattr("maverick.audit.global_audit_log", lambda: AcceptingAudit())
    lifecycle = []
    monkeypatch.setattr(
        security_api,
        "start_hunter_scheduler",
        lambda: lifecycle.append("start") or True,
    )
    monkeypatch.setattr(
        security_api,
        "stop_hunter_scheduler",
        lambda **_kwargs: lifecycle.append("stop") or True,
    )

    current = _assert_ok(client.get("/api/v1/security/config"))
    effective = _assert_ok(client.put(
        "/api/v1/security/config",
        json={
            "security_ops": False,
            "threat_hunt": False,
            "env_hunt": False,
            "response_execution": False,
            "expected_revision": current["revision"],
        },
    ))

    assert effective["threat_hunt"] is True
    assert lifecycle == ["start"]


def test_security_authority_fails_closed_on_unreadable_global_source(tmp_path, monkeypatch):
    from maverick import config, env_hunt, platform_hunt, security_ops
    from maverick_dashboard import settings_store

    operator = tmp_path / "operator.toml"
    operator.write_text("[threat_hunt\nenable = true\n", encoding="utf-8")
    monkeypatch.setenv(config.CONFIG_OVERLAY_ENV, str(operator))
    config.reset_config_cache()

    assert security_ops.enabled() is False
    assert platform_hunt.enabled() is False
    assert env_hunt.enabled() is False
    assert env_hunt.response_execution_enabled() is False
    with pytest.raises(settings_store.SecuritySuiteConfigUnavailable):
        settings_store.set_security_suite(
            security_ops=True,
            threat_hunt=True,
            env_hunt=True,
            response_execution=False,
            actor="test:admin",
            expected_revision=1,
        )
    rejected = client.put(
        "/api/v1/security/config",
        json={
            "security_ops": True,
            "threat_hunt": True,
            "env_hunt": True,
            "response_execution": False,
            "expected_revision": 1,
        },
    )
    assert rejected.status_code == 401


def test_security_config_reports_scheduler_degradation_after_durable_commit(monkeypatch):
    from maverick_dashboard import security_api

    class AcceptingAudit:
        def record(self, _event):
            return True

    monkeypatch.setattr("maverick.audit.global_audit_log", lambda: AcceptingAudit())
    monkeypatch.setattr(
        security_api,
        "start_hunter_scheduler",
        lambda: (_ for _ in ()).throw(RuntimeError("scheduler unavailable")),
    )
    current = _assert_ok(client.get("/api/v1/security/config"))
    committed = _assert_ok(
        client.put(
            "/api/v1/security/config",
            json={
                "security_ops": True,
                "threat_hunt": True,
                "env_hunt": False,
                "response_execution": False,
                "expected_revision": current["revision"],
            },
        )
    )

    assert committed["revision"] == current["revision"] + 1
    assert committed["threat_hunt"] is True
    assert committed["scheduler_degraded"] == "start_failed"
    effective = _assert_ok(client.get("/api/v1/security/config"))
    assert effective["revision"] == committed["revision"]
    assert effective["threat_hunt"] is True


def test_hunter_scheduler_explicitly_visits_every_active_tenant(monkeypatch):
    from types import SimpleNamespace

    from maverick.paths import explicit_tenant_id
    from maverick.tenant import registry
    from maverick_dashboard import automation_queue, security_api

    monkeypatch.setattr(automation_queue, "_configured_tenant_floor", lambda: "")
    monkeypatch.setattr(
        registry,
        "list_tenants",
        lambda: [
            SimpleNamespace(id="customer-a", active=True),
            SimpleNamespace(id="customer-b", active=True),
            SimpleNamespace(id="suspended", active=False),
        ],
    )
    monkeypatch.setattr(registry, "assert_tenant_active", lambda _tenant: None)
    visited = []
    monkeypatch.setattr(
        security_api,
        "_hunter_scheduler_tenant_cycle",
        lambda _owner, _config: visited.append(explicit_tenant_id()),
    )

    security_api._hunter_scheduler_cycle("scheduler:test")

    assert visited == [None, "customer-a", "customer-b"]
    assert explicit_tenant_id() is None


def test_hunter_scheduler_is_stoppable_and_lifecycle_managed(monkeypatch):
    import threading

    from maverick_dashboard import security_api

    ran = threading.Event()
    monkeypatch.setattr(
        security_api,
        "_hunter_scheduler_cycle",
        lambda _owner: ran.set(),
    )
    assert security_api.start_hunter_scheduler() is True
    assert ran.wait(2.0) is True
    assert security_api.start_hunter_scheduler() is False
    assert security_api.stop_hunter_scheduler(timeout=2.0) is True


def test_platform_scan_bootstraps_audit_custody_without_hiding_later_loss(
    _isolated_security_suite, monkeypatch,
):
    """A virgin home is initialized before verify; later deletion still alerts."""
    import shutil

    from maverick import audit
    from maverick.audit import writer as audit_writer

    # This integration regression needs the real signed writer.  The surrounding
    # API fixture normally accepts audit calls in memory because file-format
    # behavior is outside most dashboard endpoint tests.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr(audit, "record", audit_writer.record)

    first = _assert_ok(client.post("/api/v1/security/threats/scan", json={}))
    assert first["chain_status"]["intact"] is True, first
    assert first["findings_detected"] == 0
    assert first["findings_created"] == 0

    audit_dir = _isolated_security_suite["home"] / "audit"
    assert list(audit_dir.glob("*.ndjson"))
    summary = _assert_ok(client.get("/api/v1/security/threats/summary"))
    assert summary["chain_status"]["intact"] is True
    assert summary["findings"] == []

    # Model a process restart after the initialized audit directory is lost.
    # The durable hunter-store witness must prevent a second genesis bootstrap.
    audit_writer._default = None
    audit_writer._defaults.clear()
    shutil.rmtree(audit_dir)

    second = _assert_ok(client.post("/api/v1/security/threats/scan", json={}))
    assert second["chain_status"]["intact"] is False
    assert {
        item["reason"] for item in second["chain_status"]["breaks"]
    } == {"audit_directory_missing"}
    assert second["findings_detected"] == 1
    assert second["findings_created"] == 1
    recreated_rows = [
        json.loads(line)
        for path in audit_dir.glob("*.ndjson")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert not any(
        row.get("kind") == "platform_hunt_custody_initialized"
        for row in recreated_rows
    )
    assert any(row.get("kind") == "platform_hunt_detection" for row in recreated_rows)
    after_loss = _assert_ok(client.get("/api/v1/security/threats/summary"))
    assert {row["rule_id"] for row in after_loss["findings"]} == {"LW-PLAT-000"}


def test_platform_scan_fails_closed_when_custody_witness_is_not_accepted(
    monkeypatch, tmp_path,
):
    from maverick import platform_hunt
    from maverick_dashboard import security_api

    snapshot = (("audit.ndjson", True, 10, "a" * 64),)
    monkeypatch.setattr(
        platform_hunt.HuntStore,
        "ensure_audit_custody_witness",
        lambda _store: False,
    )
    monkeypatch.setattr(
        security_api,
        "_collect_platform_events",
        lambda _hours: ((), (), [tmp_path / "audit.ndjson"], tmp_path, [], snapshot, snapshot),
    )
    monkeypatch.setattr(
        security_api,
        "_audit_media_snapshot",
        lambda _paths, _audit_dir: snapshot,
    )
    monkeypatch.setattr(
        platform_hunt,
        "verify_audit_chain",
        lambda _paths, audit_dirs=(): platform_hunt.ChainIntegrityStatus(
            intact=True,
            paths_checked=("audit.ndjson", "audit-anchors"),
            checked_at=time.time(),
        ),
    )

    result = _assert_ok(client.post("/api/v1/security/threats/scan", json={}))
    assert result["chain_status"]["intact"] is False
    assert result["chain_status"]["breaks"] == [{
        "path": "audit-custody",
        "line_no": 0,
        "reason": "custody_initialization_failed",
        "detail": "signed audit custody could not be initialized",
    }]
    assert result["findings_detected"] == 1
    assert result["findings_created"] == 1


def test_platform_scan_creates_cited_investigation_is_idempotent_and_never_executes(
    monkeypatch, tmp_path,
):
    from maverick import platform_hunt
    from maverick_dashboard import security_api

    now = time.time()
    events = tuple(
        platform_hunt.HuntEvent(
            event_id=f"shield-{index}",
            source="audit",
            observed_at=now + index,
            kind="shield_block",
            actor="agent-red",
            attributes={"reason": "attempted to disable the shield"},
        )
        for index in range(1, 4)
    )
    injected = client.post(
        "/api/v1/security/threats/scan",
        json={"events": [{"kind": "shield_block"}]},
    )
    assert injected.status_code == 422
    monkeypatch.setattr(
        security_api,
        "_collect_platform_events",
        lambda _hours: (
            events,
            [],
            [tmp_path / "audit.ndjson"],
            tmp_path,
            [],
            (("audit.ndjson", True, 10, "a" * 64),),
            (("audit.ndjson", True, 10, "a" * 64),),
        ),
    )
    monkeypatch.setattr(
        security_api,
        "_audit_media_snapshot",
        lambda _paths, _audit_dir: (("audit.ndjson", True, 10, "a" * 64),),
    )
    monkeypatch.setattr(
        platform_hunt,
        "verify_audit_chain",
        lambda _paths, audit_dirs=(): platform_hunt.ChainIntegrityStatus(
            intact=True,
            paths_checked=("audit.ndjson", "audit-anchors"),
            checked_at=now,
        ),
    )
    first = _assert_ok(client.post("/api/v1/security/threats/scan", json={}))
    assert first["findings_detected"] >= 1
    assert first["findings_created"] >= 1
    assert first["investigations_created"] >= 1
    assert first["approvals_queued"] >= 1

    summary = _assert_ok(client.get("/api/v1/security/threats/summary"))
    finding = next(row for row in summary["findings"] if row["rule_id"] == "LW-PLAT-001")
    assert {item["event_id"] for item in finding["evidence"]} == {
        "shield-1", "shield-2", "shield-3"
    }
    assert all(len(item["sha256"]) == 64 for item in finding["evidence"])
    investigation = next(
        row for row in summary["investigations"]
        if finding["finding_id"] in row["finding_ids"]
    )
    assert investigation["evidence"]
    assert investigation["containment"]["evidence"]
    assert investigation["approval_id"]
    from maverick.approval_cards import decode_approval_detail
    from maverick_dashboard._shared import _world
    containment_approval = _world().get_approval(investigation["approval_id"])
    containment_card = decode_approval_detail(containment_approval.detail)
    assert containment_card is not None
    assert containment_card["action"] == "security.platform_containment"

    second = _assert_ok(client.post("/api/v1/security/threats/scan", json={}))
    assert second["findings_created"] == 0
    assert second["investigations_created"] == 0
    assert second["approvals_queued"] == 0

    triaged = _assert_ok(
        client.patch(
            f"/api/v1/security/threats/findings/{finding['finding_id']}",
            json={"changes": {"status": "triaged"}, "expected_revision": finding["revision"]},
        )
    )
    assert triaged["status"] == "triaged"
    stale = client.patch(
        f"/api/v1/security/threats/findings/{finding['finding_id']}",
        json={"changes": {"status": "closed"}, "expected_revision": finding["revision"]},
    )
    assert stale.status_code == 409
    assert client.get("/api/v1/security/threats/findings/pf_missing").status_code == 404
    assert client.post("/api/v1/security/threats/responses/execute", json={}).status_code == 404


def test_platform_scan_rejects_rows_when_signed_audit_snapshot_changes(
    monkeypatch, tmp_path,
):
    from maverick import platform_hunt
    from maverick_dashboard import security_api

    event = platform_hunt.HuntEvent(
        event_id="shield-1",
        source="audit",
        observed_at=time.time(),
        kind="shield_block",
        actor="agent-red",
        attributes={"reason": "attempted to disable the shield"},
    )
    before = (("audit.ndjson", True, 10, "a" * 64),)
    changed = (("audit.ndjson", True, 11, "b" * 64),)
    monkeypatch.setattr(
        security_api,
        "_collect_platform_events",
        lambda _hours: (
            (event,),
            [],
            [tmp_path / "audit.ndjson"],
            tmp_path,
            [],
            before,
            changed,
        ),
    )
    monkeypatch.setattr(
        security_api,
        "_audit_media_snapshot",
        lambda _paths, _audit_dir: changed,
    )
    monkeypatch.setattr(
        platform_hunt,
        "verify_audit_chain",
        lambda _paths, audit_dirs=(): platform_hunt.ChainIntegrityStatus(
            intact=True,
            paths_checked=("audit.ndjson", "audit-anchors"),
            checked_at=time.time(),
        ),
    )

    result = _assert_ok(client.post("/api/v1/security/threats/scan", json={}))
    assert result["chain_status"]["intact"] is False
    assert result["chain_status"]["breaks"][-1]["reason"] == "snapshot_changed"
    summary = _assert_ok(client.get("/api/v1/security/threats/summary"))
    assert {row["rule_id"] for row in summary["findings"]} == {"LW-PLAT-000"}


def test_platform_audit_snapshot_rejects_same_path_signed_replay(
    monkeypatch, tmp_path,
):
    """Rows are bound to captured bytes even when the pathname returns to A.

    This models an ABA rollback: the snapshot probes and later chain verifier
    both see current bytes A, while the identity-bound handle used to parse rows
    saw an older but independently valid signed prefix B.
    """
    import datetime as dt
    import hashlib

    from maverick import platform_hunt
    from maverick.audit import export as audit_export
    from maverick.audit import reader as audit_reader
    from maverick.audit import worm as audit_worm
    from maverick_dashboard import security_api

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    day = dt.datetime.now(dt.timezone.utc).date().isoformat()
    audit_path = audit_dir / f"{day}.ndjson"
    current_raw = b"current signed audit snapshot A\n"
    replay_raw = b"older valid signed audit prefix B\n"
    audit_path.write_bytes(current_raw)
    replay_row = {
        "ts": time.time(),
        "kind": "shield_block",
        "agent": "agent-red",
        "hash": "b" * 64,
        "payload": {"reason": "same-path replay fixture"},
    }

    monkeypatch.setattr(
        audit_export, "audit_event_paths", lambda **_kwargs: [audit_path],
    )
    monkeypatch.setattr(
        audit_reader, "resolve_audit_dir", lambda _tenant: audit_dir,
    )
    # The path is A before and after capture, but the already-open stable handle
    # saw B during the capture itself.
    monkeypatch.setattr(
        audit_worm, "_read_custodied_file", lambda *_args, **_kwargs: replay_raw,
    )

    def _verified_rows(raw):
        assert raw == replay_raw
        return [replay_row]

    monkeypatch.setattr(audit_worm, "_verified_chain_records", _verified_rows)

    (
        rows,
        paths,
        captured_dir,
        _cutoff,
        _baseline_cutoff,
        snapshot_before,
        snapshot_after_read,
    ) = security_api._audit_window(1)

    assert rows == [replay_row]
    before_day = next(item for item in snapshot_before if item[0] == audit_path.name)
    consumed_day = next(
        item for item in snapshot_after_read if item[0] == audit_path.name
    )
    assert before_day[3] == hashlib.sha256(current_raw).hexdigest()
    assert consumed_day[3] == hashlib.sha256(replay_raw).hexdigest()

    monkeypatch.setattr(
        platform_hunt,
        "verify_audit_chain",
        lambda _paths, audit_dirs=(): platform_hunt.ChainIntegrityStatus(
            intact=True,
            paths_checked=(audit_path.name, "audit-anchors"),
            checked_at=time.time(),
        ),
    )
    chain = security_api._verified_audit_chain(
        platform_hunt,
        paths,
        captured_dir,
        snapshot_before,
        snapshot_after_read,
    )
    assert chain.intact is False
    assert chain.breaks[-1]["reason"] == "snapshot_changed"


def test_platform_budget_detection_reads_only_verified_receipt_ledger(
    _isolated_security_suite, monkeypatch,
):
    from dataclasses import dataclass

    from maverick import budget_receipts, config
    from maverick_dashboard import security_api

    _isolated_security_suite["config"].write_text(
        """[security_ops]
enable = true
[threat_hunt]
enable = true
[env_hunt]
enable = true
[budget]
max_dollars = 1.0
""",
        encoding="utf-8",
    )
    config.reset_config_cache()
    monkeypatch.setenv("MAVERICK_RECEIPT_KEY", "receipt-test-key")

    @dataclass
    class Episode:
        started_at: float = 100.0
        ended_at: float = 101.0
        cost_dollars: float = 2.0
        input_tokens: int = 10
        output_tokens: int = 20
        cache_read_tokens: int = 0
        cache_write_tokens: int = 0
        tool_calls: int = 1

    episode = Episode()

    class World:
        def list_episodes(self, **_kwargs):
            return [episode]

    path = budget_receipts.receipts_path()
    budget_receipts.mint(
        World(), 7, "receipt-test-key", path=path, clock=lambda: 102.0,
    )
    episode.cost_dollars = 0.0
    rows, degraded = security_api._budget_receipt_hunt_rows()
    assert degraded == []
    assert rows[0]["used"] == 2.0
    assert rows[0]["limit"] == 1.0
    assert rows[0]["outcome"] == "exceeded"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace('"total_dollars":2.0', '"total_dollars":0.0'), encoding="utf-8")
    rows, degraded = security_api._budget_receipt_hunt_rows()
    assert rows == []
    assert degraded == ["budget_receipts:chain_invalid"]


def test_platform_budget_detection_rejects_a_changed_verified_snapshot(
    _isolated_security_suite, monkeypatch,
):
    from dataclasses import dataclass

    from maverick import budget_receipts
    from maverick_dashboard import security_api

    monkeypatch.setenv("MAVERICK_RECEIPT_KEY", "receipt-test-key")

    @dataclass
    class Episode:
        started_at: float = 100.0
        ended_at: float = 101.0
        cost_dollars: float = 2.0
        input_tokens: int = 10
        output_tokens: int = 20
        cache_read_tokens: int = 0
        cache_write_tokens: int = 0
        tool_calls: int = 1

    class World:
        def list_episodes(self, **_kwargs):
            return [Episode()]

    budget_receipts.mint(
        World(), 7, "receipt-test-key",
        path=budget_receipts.receipts_path(), clock=lambda: 102.0,
    )
    original_verify_chain = budget_receipts.verify_chain
    calls = 0

    def changed_count(path, key):
        nonlocal calls
        calls += 1
        report = original_verify_chain(path, key)
        if calls == 2:
            return budget_receipts.ChainReport(
                count=report.count + 1,
                broken_at=None,
            )
        return report

    monkeypatch.setattr(budget_receipts, "verify_chain", changed_count)
    rows, degraded = security_api._budget_receipt_hunt_rows()
    assert rows == []
    assert degraded == ["budget_receipts:snapshot_changed"]


def test_environment_ingest_runs_curated_and_custom_sigma_without_raw_persistence(
    _isolated_security_suite,
):
    marker = "RAW-CREDENTIAL-MARKER-7391"
    ingest = _assert_ok(
        client.post(
            "/api/v1/security/soc/ingest",
            json=_environment_attack_body(marker=marker),
        )
    )
    assert ingest["events_received"] == 2
    assert ingest["events_accepted"] == 2
    assert ingest["raw_events_persisted"] is False
    assert ingest["findings_created"] >= 3
    assert ingest["investigations_created"] >= 3
    assert ingest["response_proposals_created"] >= 1

    summary = _assert_ok(client.get("/api/v1/security/soc/summary"))
    rule_ids = {row["rule_id"] for row in summary["findings"]}
    assert {"LW-SIGMA-001", "LW-SIGMA-002", "customer-console-login"} <= rule_ids
    assert any(row["technique"] == "T1078" for row in summary["attack_heatmap"])
    assert summary["raw_events_persisted"] is False
    assert marker not in json.dumps(ingest, sort_keys=True)
    assert marker not in json.dumps(summary, sort_keys=True)
    for path in Path(_isolated_security_suite["home"]).rglob("*"):
        if path.is_file():
            assert marker.encode() not in path.read_bytes(), path

    finding = summary["findings"][0]
    updated = _assert_ok(
        client.patch(
            f"/api/v1/security/soc/findings/{finding['finding_id']}",
            json={"changes": {"status": "investigating"}, "expected_revision": finding["revision"]},
        )
    )
    assert updated["status"] == "investigating"
    stale = client.patch(
        f"/api/v1/security/soc/findings/{finding['finding_id']}",
        json={"changes": {"status": "closed"}, "expected_revision": finding["revision"]},
    )
    assert stale.status_code == 409
    assert client.get("/api/v1/security/soc/findings/ef_missing").status_code == 404
    page = client.get("/security/soc")
    assert page.status_code == 200
    assert "Your own checks" in page.text and "Add a check" in page.text
    assert "Kinds of attack seen" in page.text
    assert 'id="hunt-safety"' in page.text
    assert "A new cloud access key was created" in page.text  # built-in check library
    assert 'type="file" id="soc-file"' in page.text        # exported log file, not pasted JSON
    assert "<textarea" not in page.text
    from test_support.plain_language import developer_terms
    assert developer_terms(page.text) == []


def test_environment_auto_response_recognizes_normalized_edr_source():
    from types import SimpleNamespace

    from maverick_dashboard import security_api

    captured = {}

    class Hunter:
        @staticmethod
        def propose_response(action, target, reason, evidence, *, executor=""):
            captured.update({
                "action": action,
                "target": target,
                "reason": reason,
                "evidence": evidence,
                "executor": executor,
            })
            return captured

    finding = SimpleNamespace(
        severity="critical",
        mitre_techniques=("T1059",),
        rule_id="customer-edr-rule",
        title="Endpoint command execution",
        evidence=("evidence-ref",),
    )
    investigation = SimpleNamespace(timeline=(SimpleNamespace(
        principal="",
        category="process",
        target="workstation-17",
        source="edr.crowdstrike",
    ),))

    proposal = security_api._auto_environment_response(Hunter, finding, investigation)

    assert proposal is captured
    assert captured["action"] == "isolate_host"
    assert captured["target"] == "workstation-17"


def test_environment_push_requires_its_own_connector_opt_in(
    _isolated_security_suite,
):
    from maverick import config

    _isolated_security_suite["config"].write_text(
        """[security_ops]
enable = true
[threat_hunt]
enable = true
[env_hunt]
enable = true
[env_hunt.connectors.cloudtrail]
enable = true
push_enable = false
""",
        encoding="utf-8",
    )
    config.reset_config_cache()
    response = client.post(
        "/api/v1/security/soc/ingest", json=_environment_attack_body(),
    )
    assert response.status_code == 403
    assert "web-push" in response.json()["detail"]


def test_environment_ingestion_and_detection_audit_fail_closed(monkeypatch):
    from maverick import audit
    from maverick_dashboard import security_api

    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    response = client.post(
        "/api/v1/security/soc/ingest", json=_environment_attack_body(),
    )
    assert response.status_code == 503
    assert security_api._environment_store().list_findings() == []
    monkeypatch.setattr(
        audit,
        "record",
        lambda kind, **_kwargs: str(kind) == "env_hunt_ingestion",
    )
    detection_refused = client.post(
        "/api/v1/security/soc/ingest", json=_environment_attack_body(),
    )
    assert detection_refused.status_code == 503
    assert security_api._environment_store().list_findings() == []


def test_missing_shield_keeps_detection_but_suppresses_autonomy(monkeypatch):
    from maverick import shield_policy

    monkeypatch.setattr(shield_policy, "shield_available", lambda: False)
    ingest = _assert_ok(
        client.post("/api/v1/security/soc/ingest", json=_environment_attack_body())
    )
    assert ingest["findings_detected"] >= 1
    assert ingest["reduced_autonomy"] is True
    assert ingest["response_proposals_created"] == 0
    assert ingest["approvals_queued"] == 0
    blocked_execution = client.post(
        "/api/v1/security/soc/responses/execute",
        json={
            "investigation_id": "inv-missing",
            "proposal_id": "response-missing",
            "approval_id": 1,
            "executor": "test-edr",
            "signature": "0" * 128,
            "expected_revision": 1,
        },
    )
    assert blocked_execution.status_code == 403
    assert "reduced-autonomy" in blocked_execution.json()["detail"]


def test_registered_pull_connector_pivots_and_persists_allowlisted_enrichment(
    _isolated_security_suite,
):
    from dataclasses import dataclass

    from maverick import config
    from maverick_dashboard import security_api

    _isolated_security_suite["config"].write_text(
        """[security_ops]
enable = true
[threat_hunt]
enable = true
[env_hunt]
enable = true
[env_hunt.connectors.cloudtrail]
enable = true
push_enable = false
pivot_enable = true
[env_hunt.enrichment_sources.approved_intel]
enable = true
""",
        encoding="utf-8",
    )
    config.reset_config_cache()
    calls = []

    def transport(request):
        calls.append(request)
        if request.query == "lightwork:related-events-v1":
            return [{
                "eventID": "cloud-related-1",
                "eventTime": 1_020,
                "eventName": "DeleteTrail",
                "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
                "requestParameters": {"resource": "evil.example.com"},
            }]
        return [
            {
                "eventID": "cloud-login-pull",
                "eventTime": 1_000,
                "eventName": "ConsoleLogin",
                "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
                "additionalEventData": {"MFAUsed": "No"},
                "requestParameters": {"resource": "evil.example.com"},
            },
            {
                "eventID": "cloud-key-pull",
                "eventTime": 1_010,
                "eventName": "CreateAccessKey",
                "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
                "requestParameters": {"resource": "evil.example.com"},
            },
        ]

    @dataclass
    class Provider:
        name: str = "approved_intel"
        calls: int = 0

        def lookup(self, indicator):
            self.calls += 1
            return {
                "reputation": "malicious",
                "confidence": 95,
                "raw_payload": "must-not-persist",
            }

    provider = Provider()
    security_api.register_environment_connector_transport("cloudtrail", transport)
    security_api.register_environment_enrichment_provider(provider)
    ingest = _assert_ok(
        client.post(
            "/api/v1/security/soc/ingest",
            json={
                "connector": "cloudtrail",
                "start": 900,
                "end": 1_100,
                "limit": 100,
            },
        )
    )
    assert ingest["ingestion_mode"] == "registered_transport"
    assert ingest["investigation_pivot_events"] == 1
    assert len(calls) == 2
    assert calls[1].limit <= 1_000
    assert calls[1].filters["lightwork_related_targets"] == ["evil.example.com"]
    summary = _assert_ok(client.get("/api/v1/security/soc/summary"))
    investigation = next(
        row for row in summary["investigations"]
        if any(item["event_id"] == "cloud-related-1" for item in row["timeline"])
    )
    assert investigation["enrichments"]
    assert investigation["enrichments"][0]["fields"] == {
        "confidence": 95,
        "reputation": "malicious",
    }
    assert provider.calls >= 1


def test_trusted_environment_adapters_are_exactly_tenant_bound(
    _isolated_security_suite,
):
    from dataclasses import dataclass

    from maverick import config, env_hunt
    from maverick.paths import tenant_scope
    from maverick_dashboard import security_api

    _isolated_security_suite["config"].write_text(
        """[env_hunt]
enable = true
[env_hunt.connectors.cloudtrail]
enable = true
push_enable = false
pivot_enable = false
[env_hunt.enrichment_sources.approved_intel]
enable = true
""",
        encoding="utf-8",
    )
    config.reset_config_cache()

    def transport_a(_request):
        return [{
            "eventID": "customer-a-secret-event",
            "eventTime": 1_000,
            "eventName": "GetSecretValue",
            "userIdentity": {"arn": "arn:customer-a:secret"},
        }]

    def transport_b(_request):
        return [{
            "eventID": "customer-b-event",
            "eventTime": 1_000,
            "eventName": "ListBuckets",
            "userIdentity": {"arn": "arn:customer-b:user"},
        }]

    @dataclass
    class Provider:
        marker: str
        name: str = "approved_intel"

        def lookup(self, _indicator):
            return {"marker": self.marker}

    class Executor:
        name = "tenant-edr"

        def __init__(self, marker):
            self.marker = marker

        def execute(self, candidate, governed_approval):
            return env_hunt.ResponseReceipt(
                candidate.proposal_id,
                governed_approval.approval_id,
                self.name,
                self.marker,
            )

    provider_a = Provider("customer-a")
    executor_a = Executor("customer-a")
    with tenant_scope(tenant="customer-a"):
        security_api.register_environment_connector_transport(
            "cloudtrail", transport_a,
        )
        security_api.register_environment_enrichment_provider(provider_a)
        security_api.environment_response_registry().register(executor_a)

        factory = security_api._configured_environment_connector_factory(env_hunt)
        connector = factory.build_connector("cloudtrail")
        request = env_hunt.QueryRequest(
            start=900, end=1_100, limit=10, read_only=True,
        )
        assert [event.event_id for event in connector.fetch(request)] == [
            "customer-a-secret-event"
        ]
        providers, allowed = security_api._configured_environment_enrichment_providers()
        assert providers == (provider_a,)
        assert allowed == ("approved_intel",)
        assert security_api.environment_response_registry().get("tenant-edr") is executor_a

    with tenant_scope(tenant="customer-b"):
        factory = security_api._configured_environment_connector_factory(env_hunt)
        with pytest.raises(env_hunt.ConnectorUnavailable):
            factory.build_connector("cloudtrail")
        providers, allowed = security_api._configured_environment_enrichment_providers()
        assert providers == ()
        assert allowed == ("approved_intel",)
        assert security_api.environment_response_registry().names() == ()

        provider_b = Provider("customer-b")
        executor_b = Executor("customer-b")
        security_api.register_environment_connector_transport(
            "cloudtrail", transport_b,
        )
        security_api.register_environment_enrichment_provider(provider_b)
        security_api.environment_response_registry().register(executor_b)
        connector = security_api._configured_environment_connector_factory(
            env_hunt,
        ).build_connector("cloudtrail")
        assert [event.event_id for event in connector.fetch(request)] == [
            "customer-b-event"
        ]
        providers, _allowed = security_api._configured_environment_enrichment_providers()
        assert providers == (provider_b,)
        assert security_api.environment_response_registry().get("tenant-edr") is executor_b


def test_environment_response_requires_executor_opt_in_and_exact_approval_binding(
    _isolated_security_suite, monkeypatch,
):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from maverick import config, env_hunt
    from maverick.approval_signing import sign_request
    from maverick_dashboard import security_api
    from maverick_dashboard._shared import _world

    class TestExecutor:
        name = "test-edr"
        approval_revision = "test-edr.v1"
        approval_credential_sha256 = "a" * 64

        def __init__(self):
            self.calls = 0

        def execute(self, candidate, governed_approval):
            self.calls += 1
            return env_hunt.ResponseReceipt(
                candidate.proposal_id,
                governed_approval.approval_id,
                self.name,
                "isolated",
            )

    executor = TestExecutor()
    security_api.environment_response_registry().register(executor)
    _ingest, investigation, proposal = _ingest_environment_attack()
    approval_id = int(investigation["approval_id"])
    world = _world()
    decider = "human:change-board"
    assert world.decide_approval(
        approval_id, "approved", decided_by=decider
    ) is True
    proposal_model = security_api._response_proposal_from_record(proposal)
    current_approval = world.get_approval(approval_id)
    from dataclasses import replace

    from maverick.approval_cards import decode_approval_detail
    response_card = decode_approval_detail(current_approval.detail)
    assert response_card is not None
    assert response_card["inputs"] == {"proposal_sha256": proposal_model.digest}
    assert response_card["credentials"]["revision"] == "test-edr.v1"
    assert response_card["credentials"]["credential_sha256"] == "a" * 64
    assert security_api._world_approval_matches(
        proposal_model, current_approval, approval_id
    )
    changed_proposal = replace(
        proposal_model,
        parameters={**proposal_model.parameters, "changed": True},
    )
    assert not security_api._world_approval_matches(
        changed_proposal, current_approval, approval_id
    )
    private = ed25519.Ed25519PrivateKey.generate()
    private_hex = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    signature = sign_request(
        env_hunt.response_approval_request(
            proposal_model,
            approval_id=str(approval_id),
            approved_by=decider,
        ),
        private_hex,
    )
    base = {
        "investigation_id": investigation["investigation_id"],
        "proposal_id": proposal["proposal_id"],
        "approval_id": approval_id,
        "executor": executor.name,
        "signature": signature,
        "expected_revision": investigation["revision"],
    }
    missing_trust = client.post(
        "/api/v1/security/soc/responses/execute", json=base,
    )
    assert missing_trust.status_code == 403
    assert "approver keys" in missing_trust.json()["detail"]
    monkeypatch.setattr("maverick._STARTUP_APPROVER_KEYS", public_hex)
    swapped_executor = client.post(
        "/api/v1/security/soc/responses/execute",
        json={**base, "executor": "another-edr"},
    )
    assert swapped_executor.status_code == 403

    class SameNameReplacement:
        name = "test-edr"
        approval_revision = "test-edr.v2"
        approval_credential_sha256 = "b" * 64

        def execute(self, candidate, governed_approval):
            raise AssertionError("drifted executor must never run")

    registry = security_api.environment_response_registry()
    registry._executors[executor.name] = SameNameReplacement()
    drifted = client.post(
        "/api/v1/security/soc/responses/execute",
        json=base,
    )
    assert drifted.status_code == 403
    assert "current executor binding" in drifted.json()["detail"]
    registry._executors[executor.name] = executor

    disabled = client.post(
        "/api/v1/security/soc/responses/execute",
        json=base,
    )
    assert disabled.status_code == 403
    assert "disabled" in disabled.json()["detail"]
    assert executor.calls == 0

    wrong_binding = client.post(
        "/api/v1/security/soc/responses/execute",
        json={**base, "approval_id": approval_id + 999},
    )
    assert wrong_binding.status_code == 403
    assert executor.calls == 0

    # Explicitly arm the second gate, then prove the exact attached approval is
    # executable and a different, merely-approved row is not.
    config_path = _isolated_security_suite["config"]
    config_path.write_text(
        """[security_ops]
enable = true
[threat_hunt]
enable = true
[env_hunt]
enable = true
response_execution = true

[env_hunt.connectors.cloudtrail]
enable = true
push_enable = true
pivot_enable = false
""",
        encoding="utf-8",
    )
    config.reset_config_cache()
    real_actor = security_api._actor
    actors = iter(("user:admin", "user:mallory"))
    monkeypatch.setattr(security_api, "_actor", lambda _request: next(actors))
    authority_drift = client.post(
        "/api/v1/security/soc/responses/execute",
        json=base,
    )
    assert authority_drift.status_code == 403
    assert "authority changed" in authority_drift.json()["detail"]
    assert executor.calls == 0
    monkeypatch.setattr(security_api, "_actor", real_actor)
    executed = _assert_ok(
        client.post(
            "/api/v1/security/soc/responses/execute",
            json=base,
        )
    )
    assert executed["outcome"] == "isolated"
    assert executor.calls == 1
    replay = _assert_ok(
        client.post("/api/v1/security/soc/responses/execute", json=base)
    )
    assert replay == executed
    assert executor.calls == 1

    replacement_id = world.create_approval(
        "security.environment_response",
        risk="critical",
        scope=proposal["target"],
        detail=security_api._environment_response_approval_detail(proposal_model),
        provenance="security.env_hunt.response.v1",
        requested_by="system:env_hunt",
    )
    assert world.decide_approval(
        replacement_id, "approved", decided_by=decider
    ) is True
    store = security_api._environment_store()
    latest = store.get_investigation(investigation["investigation_id"])
    approvals = dict(latest.get("response_approval_ids") or {})
    approvals[proposal["proposal_id"]] = replacement_id
    replaced = store.update_investigation(
        investigation["investigation_id"],
        {"approval_id": replacement_id, "response_approval_ids": approvals},
        expected_revision=latest["revision"],
        actor="test:tamper",
    )
    rejected = client.post(
        "/api/v1/security/soc/responses/execute",
        json={
            **base,
            "approval_id": replacement_id,
            "expected_revision": replaced["revision"],
        },
    )
    assert rejected.status_code == 403
    assert "verified" in rejected.json()["detail"]
    assert executor.calls == 1
