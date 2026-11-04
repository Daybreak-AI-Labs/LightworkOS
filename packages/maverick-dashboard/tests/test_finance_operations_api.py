"""HTTP contracts for the deterministic finance-operations surface."""
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick_dashboard import finance_api


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    from maverick import audit, config, governed_records
    from maverick.audit import writer as audit_writer

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """[finance_operations]
enable = true
control_test_interval_seconds = 86400

[security_ops]
enable = true
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in (
        "MAVERICK_TENANT",
        "MAVERICK_TENANT_BY_USER",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    governed_records._reset_process_authority_pin_for_testing()

    permission_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        finance_api,
        "require_permission",
        lambda _request, permission, **_scope: permission_calls.append(("tenant", permission)),
    )
    monkeypatch.setattr(
        finance_api,
        "require_global_permission",
        lambda _request, permission: permission_calls.append(("global", permission)),
    )
    monkeypatch.setattr(
        finance_api,
        "_actor",
        lambda request: request.headers.get("X-Test-Actor", "operator@example.com"),
    )

    app = FastAPI()
    app.include_router(finance_api.router)
    with TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False) as client:
        yield client, permission_calls

    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    governed_records._reset_process_authority_pin_for_testing()


def _ok(response, expected: int = 200):
    assert response.status_code == expected, response.text
    return response.json()


def _regulatory_ingest(client: TestClient) -> dict:
    payload = json.dumps(
        {
            "items": [
                {
                    "id": "rule-1",
                    "title": "Money transmitter renewal rule",
                    "summary": "Cited deterministic fixture",
                    "published_at": "2026-07-22",
                    "url": "https://regulator.example.gov/rules/1",
                    "citation": "State Register 2026-1",
                }
            ]
        }
    )
    return _ok(
        client.post(
            "/finance-operations/regulatory/feeds/ingest",
            headers={"X-Test-Actor": "admin@example.com"},
            json={
                "source": {
                    "key": "state-register",
                    "name": "Official State Register",
                    "jurisdiction": "US-NY",
                    "url": "https://regulator.example.gov/feed.json",
                    "format": "json",
                    "default_domains": ["money_transmitter"],
                },
                "payload": payload,
                "enabled_domains": ["money_transmitter"],
            },
        )
    )


def test_regulatory_review_and_licensing_register_are_cited_and_permissioned(api_client):
    client, calls = api_client
    ingested = _regulatory_ingest(client)
    assert ingested["alerts_created"] == 1

    alerts = _ok(client.get("/finance-operations/regulatory/alerts"))["alerts"]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["official_citation"] == "State Register 2026-1"
    assert "citations" not in alert
    assert "diff" not in alert
    detail = _ok(
        client.get(f"/finance-operations/regulatory/alerts/{alert['alert_id']}")
    )
    citation = detail["alert"]["citations"][0]
    assert citation["feed_url"].endswith("/feed.json")
    assert citation["acquisition"] == "operator_supplied"
    assert citation["acquired_by"] == "admin@example.com"
    assert citation["retrieval_url"].startswith("urn:lightwork:")
    assert detail["review_history"] == []
    reviewed = _ok(
        client.post(
            f"/finance-operations/regulatory/alerts/{alert['alert_id']}/review",
            headers={"X-Test-Actor": "reviewer@example.com"},
            json={
                "status": "accepted",
                "note": "Mapped to FIN-RCM-01.",
                "expected_revision": alert["revision"],
            },
        )
    )
    assert reviewed["status"] == "accepted"
    assert reviewed["reviewer"] == "reviewer@example.com"

    packs = _ok(client.get("/finance-operations/licensing/packs"))["packs"]
    assert {row["vertical"] for row in packs} == {
        "money_transmitter",
        "insurance_producer",
    }
    projection = _ok(
        client.get(
            "/finance-operations/licensing/packs/money_transmitter/register"
        )
    )
    assert len(projection["records"]) == 50
    assert all(row["citation_urls"] for row in projection["records"])
    assert all(len(row["pack_sha256"]) == 64 for row in projection["records"])

    assert ("global", "admin") in calls
    assert ("tenant", "view") in calls
    assert ("tenant", "operate") in calls


def test_regulatory_alert_api_exposes_cursor_pages(api_client):
    client, _calls = api_client
    _regulatory_ingest(client)

    first = _ok(
        client.get("/finance-operations/regulatory/alerts", params={"limit": 1})
    )
    assert first["schema"] == "lightwork.regulatory-alert-page.v1"
    assert first["has_more"] is False
    assert first["next_cursor"] == ""
    assert len(first["alerts"]) == 1

    invalid = client.get(
        "/finance-operations/regulatory/alerts",
        params={"cursor": "not-a-valid-cursor"},
    )
    assert invalid.status_code == 422


def test_manual_regulatory_ingest_rejects_conflicting_duplicate_ids_atomically(
    api_client,
):
    client, _calls = api_client
    response = client.post(
        "/finance-operations/regulatory/feeds/ingest",
        headers={"X-Test-Actor": "admin@example.com"},
        json={
            "source": {
                "key": "manual-conflict",
                "name": "Official State Register",
                "jurisdiction": "US-NY",
                "url": "https://regulator.example.gov/feed.json",
                "format": "json",
                "default_domains": ["money_transmitter"],
            },
            "payload": json.dumps({"items": [
                {
                    "id": "duplicate-id",
                    "title": "Money transmitter first version",
                    "url": "https://regulator.example.gov/rules/duplicate-id",
                },
                {
                    "id": "duplicate-id",
                    "title": "Money transmitter conflicting version",
                    "url": "https://regulator.example.gov/rules/duplicate-id",
                },
            ]}),
            "enabled_domains": ["money_transmitter"],
        },
    )

    assert response.status_code == 422
    assert _ok(client.get("/finance-operations/regulatory/alerts"))["alerts"] == []


def test_manual_regulatory_ingest_cannot_override_tenant_enabled_scopes(api_client):
    client, _calls = api_client
    result = _ok(client.post(
        "/finance-operations/regulatory/feeds/ingest",
        headers={"X-Test-Actor": "admin@example.com"},
        json={
            "source": {
                "key": "scope-override",
                "name": "Official State Register",
                "jurisdiction": "US-NY",
                "url": "https://regulator.example.gov/feed.json",
                "format": "json",
            },
            "payload": json.dumps({"items": [{
                "id": "lending-only",
                "title": "Consumer lending license notice",
                "url": "https://regulator.example.gov/rules/lending-only",
            }]}),
            "enabled_domains": ["lending"],
        },
    ))

    assert result["versions_created"] == 1
    assert result["alerts_created"] == 0
    assert _ok(client.get("/finance-operations/regulatory/alerts"))["alerts"] == []


def test_anomaly_scan_route_enforces_kill_switch(api_client, monkeypatch):
    from maverick.finance import anomaly_engine

    client, _calls = api_client
    monkeypatch.setattr(anomaly_engine, "enabled", lambda: False)
    response = client.post(
        "/finance-operations/anomalies/scan",
        json={
            "transactions": [{
                "transaction_id": "disabled-1",
                "amount": "1",
                "currency": "USD",
                "posted_at": "2026-07-20T14:00:00Z",
                "source_system": "erp-ap",
                "source_record_id": "payment/disabled-1",
            }]
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "finance anomaly scanning is disabled"


def test_anomaly_scan_persists_cases_and_enforces_cas_and_four_eyes(api_client):
    client, _calls = api_client
    body = {
        "transactions": [
            {
                "transaction_id": "tx-1",
                "amount": "1250.00",
                "currency": "USD",
                "posted_at": "2026-07-20T14:00:00Z",
                "source_system": "erp-ap",
                "source_record_id": "payment/tx-1",
                "counterparty_id": "vendor-1",
                "invoice_id": "INV-9",
            },
            {
                "transaction_id": "tx-2",
                "amount": "1250",
                "currency": "USD",
                "posted_at": "2026-07-20T15:00:00Z",
                "source_system": "erp-ap",
                "source_record_id": "payment/tx-2",
                "counterparty_id": "vendor-1",
                "invoice_id": "inv-9",
            },
        ],
        "enqueue_findings": True,
    }
    scanned = _ok(
        client.post(
            "/finance-operations/anomalies/scan",
            headers={"X-Test-Actor": "analyst@example.com"},
            json=body,
        )
    )
    duplicate_cases = [
        row
        for row in scanned["cases"]
        if row["finding"]["rule_id"] == "finance.duplicate_payment"
    ]
    assert len(duplicate_cases) == 1
    case = duplicate_cases[0]
    assert case["severity"] == "high"
    case_id = case["id"]

    dispositioned = _ok(
        client.post(
            f"/finance-operations/anomalies/cases/{case_id}/disposition",
            headers={"X-Test-Actor": "investigator@example.com"},
            json={
                "outcome": "confirmed",
                "rationale": "Invoice and exact source records were reviewed.",
                "expected_revision": case["revision"],
            },
        )
    )
    assert dispositioned["status"] == "dispositioned"

    same_reviewer = client.post(
        f"/finance-operations/anomalies/cases/{case_id}/closure",
        headers={"X-Test-Actor": "investigator@example.com"},
        json={
            "rationale": "Attempted same-reviewer closure.",
            "expected_revision": dispositioned["revision"],
        },
    )
    assert same_reviewer.status_code == 422

    closed = _ok(
        client.post(
            f"/finance-operations/anomalies/cases/{case_id}/closure",
            headers={"X-Test-Actor": "supervisor@example.com"},
            json={
                "rationale": "Independent review completed.",
                "expected_revision": dispositioned["revision"],
            },
        )
    )
    assert closed["status"] == "closed"
    assert closed["closure"]["four_eyes_satisfied"] is True

    stale = client.post(
        f"/finance-operations/anomalies/cases/{case_id}/disposition",
        headers={"X-Test-Actor": "other@example.com"},
        json={
            "outcome": "false_positive",
            "rationale": "Stale browser state.",
            "expected_revision": case["revision"],
        },
    )
    assert stale.status_code == 409
    assert client.get("/finance-operations/anomalies/cases/missing").status_code == 404


def test_anomaly_case_api_exposes_bounded_cursor_pages(api_client):
    client, _calls = api_client
    scanned = _ok(
        client.post(
            "/finance-operations/anomalies/scan",
            headers={"X-Test-Actor": "analyst@example.com"},
            json={
                "transactions": [
                    {
                        "transaction_id": f"off-hours-{index}",
                        "amount": str(index + 1),
                        "currency": "USD",
                        "posted_at": "2026-07-20T03:00:00Z",
                        "source_system": "erp-gl",
                        "source_record_id": f"posting/{index}",
                        "counterparty_id": f"vendor-{index}",
                    }
                    for index in range(2)
                ],
                "enqueue_findings": True,
            },
        )
    )
    assert len(scanned["cases"]) == 2

    first = _ok(
        client.get("/finance-operations/anomalies/cases", params={"limit": 1})
    )
    assert first["schema"] == "lightwork.finance-anomaly-case-page.v1"
    assert first["has_more"] is True
    assert first["next_cursor"]
    assert len(first["cases"]) == 1

    second = _ok(
        client.get(
            "/finance-operations/anomalies/cases",
            params={"limit": 1, "cursor": first["next_cursor"]},
        )
    )
    assert second["has_more"] is False
    assert second["next_cursor"] == ""
    assert len(second["cases"]) == 1
    assert second["cases"][0]["id"] != first["cases"][0]["id"]

    invalid = client.get(
        "/finance-operations/anomalies/cases",
        params={"cursor": "not-a-valid-cursor"},
    )
    assert invalid.status_code == 422


def test_aml_metadata_never_exposes_entries_and_cases_need_two_reviewers(api_client):
    client, _calls = api_client
    ingested = _ok(
        client.post(
            "/finance-operations/aml/lists/ingest",
            headers={"X-Test-Actor": "list-admin@example.com"},
            json={
                "list_kind": "sanctions",
                "source_name": "Operator-provided sanctions fixture",
                "source_ref": "urn:operator:screening-fixture",
                "version": "2026-07-22",
                "data_format": "json",
                "payload": json.dumps(
                    [{"id": "sdn-1", "name": "Acme Shipping", "aliases": ["Acme Shiping"]}]
                ),
            },
        )
    )
    assert ingested["entry_count"] == 1
    assert "entries" not in ingested
    metadata = _ok(client.get("/finance-operations/aml/lists"))["lists"]
    assert metadata[0]["content_sha256"] == ingested["content_sha256"]
    assert all("entries" not in row for row in metadata)
    detail = _ok(client.get(f"/finance-operations/aml/lists/{ingested['id']}"))
    assert "entries" not in detail

    screened = _ok(
        client.post(
            "/finance-operations/aml/screen",
            headers={"X-Test-Actor": "submitter@example.com"},
            json={
                "subject_name": "Acme Shiping",
                "subject_ref": "customer-42",
                "list_ids": [ingested["id"]],
            },
        )
    )
    assert screened["match"] is True
    case = screened["case"]

    submitter_blocked = client.post(
        f"/finance-operations/aml/cases/{case['id']}/disposition",
        headers={"X-Test-Actor": "submitter@example.com"},
        json={
            "decision": "escalate",
            "rationale": "The submitter cannot review the case.",
            "expected_revision": case["revision"],
        },
    )
    assert submitter_blocked.status_code == 422

    first = _ok(
        client.post(
            f"/finance-operations/aml/cases/{case['id']}/disposition",
            headers={"X-Test-Actor": "reviewer-one@example.com"},
            json={
                "decision": "escalate",
                "rationale": "Potential match requires enhanced review.",
                "expected_revision": case["revision"],
            },
        )
    )
    assert first["status"] == "pending_second_review"
    second = _ok(
        client.post(
            f"/finance-operations/aml/cases/{case['id']}/disposition",
            headers={"X-Test-Actor": "reviewer-two@example.com"},
            json={
                "decision": "escalate",
                "rationale": "Independent match review agrees.",
                "expected_revision": first["revision"],
            },
        )
    )
    assert second["status"] == "escalated"
    assert len(second["final_disposition"]["reviewers"]) == 2
    adjudication_queue = _ok(
        client.get(
            "/finance-operations/aml/cases",
            params={"status": "pending_adjudication_review"},
        )
    )
    assert adjudication_queue["cases"] == []


def test_summary_is_aggregate_and_internal_failures_are_redacted(api_client, monkeypatch):
    client, _calls = api_client
    summary = _ok(client.get("/finance-operations/summary"))
    assert summary["enabled"] is True
    assert set(summary) == {
        "enabled",
        "regulatory_alerts",
        "licensing_packs",
        "anomaly_cases",
        "aml",
        "control_cycles",
    }
    rendered = json.dumps(summary).lower()
    assert "subject_name" not in rendered
    assert "transaction_id" not in rendered
    assert "entry_name" not in rendered
    assert "aliases" not in rendered
    assert summary["aml"]["list_versions_truncated"] is False
    assert summary["aml"]["cases_truncated"] is False
    assert summary["control_cycles"]["truncated"] is False

    class BrokenEngine:
        def list_alerts(self, **_kwargs):
            raise RuntimeError(
                "postgres://secret-user:secret-password@example.invalid/db"  # pragma: allowlist secret
            )

    monkeypatch.setattr(finance_api, "_regulatory_engine", lambda: BrokenEngine())
    failed = client.get("/finance-operations/regulatory/alerts")
    assert failed.status_code == 503
    assert failed.json() == {"detail": "finance operation failed safely"}
    assert "secret-password" not in failed.text


def test_control_cycle_surface_and_validation_are_bounded(api_client, monkeypatch):
    client, calls = api_client
    from maverick.finance import control_testing

    cycle = {
        "id": "FCT-abc",
        "status": "pending_human_evidence",
        "revision": 1,
        "observations": [],
    }
    monkeypatch.setattr(
        control_testing,
        "list_cycle_summaries",
        lambda **_kwargs: {
            "cycles": [cycle],
            "count_cap": 25,
            "truncated": False,
            "has_more": False,
            "next_cursor": "",
            "record_reads": 1,
            "order": "cycle_id_ascending",
        },
    )
    monkeypatch.setattr(
        control_testing,
        "get_cycle",
        lambda cycle_id: cycle if cycle_id == cycle["id"] else None,
    )
    monkeypatch.setattr(
        control_testing,
        "run_control_cycle",
        lambda **kwargs: {**cycle, "started_by": kwargs["actor"]},
    )
    monkeypatch.setattr(
        control_testing,
        "reconcile_control_cycle",
        lambda cycle_id, **kwargs: None if cycle_id != cycle["id"] else {
            **cycle,
            "id": cycle_id,
            "status": "human_review_passed",
            "reconciled_by": kwargs["actor"],
        },
    )

    listed = _ok(client.get("/finance-operations/control-cycles"))
    assert listed["cycles"][0]["id"] == cycle["id"]
    triggered = _ok(
        client.post(
            "/finance-operations/control-cycles/trigger",
            headers={"X-Test-Actor": "grc-admin@example.com"},
            json={},
        )
    )
    assert triggered["started_by"] == "grc-admin@example.com"
    assert ("global", "admin") in calls
    reconciled = _ok(
        client.post(
            f"/finance-operations/control-cycles/{cycle['id']}/reconcile",
            headers={"X-Test-Actor": "grc-admin@example.com"},
        )
    )
    assert reconciled["status"] == "human_review_passed"
    assert reconciled["reconciled_by"] == "grc-admin@example.com"
    assert client.post(
        "/finance-operations/control-cycles/missing/reconcile",
        headers={"X-Test-Actor": "grc-admin@example.com"},
    ).status_code == 404
    assert client.get("/finance-operations/control-cycles/missing").status_code == 404
    caller_time = client.post(
        "/finance-operations/control-cycles/trigger",
        headers={"X-Test-Actor": "grc-admin@example.com"},
        json={"now": 4_102_444_800.0},
    )
    assert caller_time.status_code == 422

    invalid = client.post(
        "/finance-operations/regulatory/feeds/ingest",
        json={
            "source": {
                "key": "bad",
                "name": "Not secure",
                "jurisdiction": "US",
                "url": "http://example.invalid/feed",
                "format": "json",
            },
            "payload": "{}",
        },
    )
    assert invalid.status_code == 422


def test_disabled_gate_is_fail_closed(api_client, monkeypatch):
    client, _calls = api_client
    monkeypatch.setattr(
        finance_api,
        "_ensure_enabled",
        lambda: (_ for _ in ()).throw(
            finance_api.HTTPException(status_code=403, detail="disabled")
        ),
    )
    response = client.get("/finance-operations/summary")
    assert response.status_code == 403
    assert response.json() == {"detail": "disabled"}
