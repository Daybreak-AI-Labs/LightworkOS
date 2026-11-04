from __future__ import annotations

import hashlib

from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick import third_party_executive_reports as reports
from maverick_dashboard import third_party_executive_reports_api as api


class Store:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def list_reports(self, *, caller_role, limit):
        self.calls.append(("list", (caller_role, limit)))
        return ()

    def get_report(self, report_id, *, caller_role):
        self.calls.append(("get", (report_id, caller_role)))
        raise reports.ThirdPartyExecutiveReportNotFound("executive_report_not_found")

    def issue_download_grant(
        self,
        report_id,
        *,
        caller_role,
        expected_control_revision,
        idempotency_key,
    ):
        self.calls.append(("grant", report_id))
        return reports.DownloadGrant(
            reports.GRANT_SCHEMA,
            "grant-1",
            report_id,
            expected_control_revision,
            1_900_000_000.0,
            "tpr_" + "A" * 43,
            True,
            False,
        )

    def redeem_download_token(self, token, *, caller_role):
        self.calls.append(("redeem", (token, caller_role)))
        payload = b"%PDF-1.4\n%%EOF\n"
        return reports.DownloadArtifact(
            "report-1",
            hashlib.sha256(payload).hexdigest(),
            payload,
        )

    def revoke_report(self, report_id, **_kwargs):
        self.calls.append(("revoke", report_id))
        return {"report_id": report_id, "state": "revoked"}

    def purge_expired(self, **_kwargs):
        self.calls.append(("purge", None))
        return ("report-1",)

    def audit_history(self, *, limit):
        self.calls.append(("audit", limit))
        return ({"action": "report_created"},)

    def verify_integrity(self):
        self.calls.append(("integrity", None))
        return reports.IntegrityVerification(
            reports=1,
            tombstones=0,
            artifacts=1,
            grants=0,
            operations=1,
            audit_events=1,
            audit_checkpoint_sequence=0,
            audit_checkpoint_sha256="0" * 64,
            terminal_audit_sha256="0" * 64,
        )


class Runtime:
    def __init__(self) -> None:
        self.store = Store()
        self.role_view = "operator"
        self.created = None

    def create_report(self, **kwargs):
        self.created = kwargs
        return {
            "report_id": kwargs["report_id"] or "generated-report",
            "role_view": self.role_view,
            "state": "active",
        }


def client(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-alpha")
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(api, "has_permission", lambda _request, _permission: True)
    app = FastAPI()
    app.state.third_party_executive_reports_runtime_factory = (
        lambda **_kwargs: runtime
    )
    app.state.third_party_executive_reports_enabled_probe = lambda _tenant: True
    app.state.third_party_executive_reports_readiness_probe = lambda _tenant: True
    app.include_router(api.create_third_party_executive_reports_router())
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), runtime


def test_status_is_store_free_and_truthful(monkeypatch) -> None:
    selected, runtime = client(monkeypatch)
    response = selected.get("/third-party/executive-reports/status")
    assert response.status_code == 200
    assert response.json() == {
        "schema": "lightwork.third-party-executive-reports-status.v1",
        "enabled": True,
        "ready": True,
        "deterministic_pdf": True,
        "arbitrary_html_css_urls": False,
        "brand_asset_bytes_embedded": False,
        "live_portfolio_acceptance_verified": False,
    }
    assert runtime.store.calls == []
    assert response.headers["cache-control"] == "no-store, private, max-age=0"


def test_create_accepts_only_closed_brand_and_source_selectors(monkeypatch) -> None:
    selected, runtime = client(monkeypatch)
    payload = {
        "report_id": "report-1",
        "expected_absent_revision": 0,
        "selectors": [
            {"source_kind": "contract_record", "source_id": "contract-1"}
        ],
        "brand": {
            "organization_name": "Lightwork",
            "report_title": "Executive report",
            "footer_text": "Governed record",
            "primary_color": "#102A43",
            "accent_color": "#2CB1BC",
            "text_color": "#243B53",
            "brand_asset_metadata_ref": None,
            "brand_asset_metadata_sha256": None,
        },
        "idempotency_key": "create-report-0001",
    }
    response = selected.post("/third-party/executive-reports/reports", json=payload)
    assert response.status_code == 201
    assert response.json()["role_view"] == "operator"
    assert runtime.created is not None
    assert runtime.created["selectors"] == (
        reports.SourceSelector("contract_record", "contract-1"),
    )
    for forbidden in ("tenant_id", "principal_ref", "role_view", "actor_ref"):
        bad = dict(payload)
        bad[forbidden] = "caller-authored"
        assert selected.post(
            "/third-party/executive-reports/reports", json=bad
        ).status_code == 422
    bad_brand = {**payload, "brand": {**payload["brand"], "custom_css": "body{}"}}
    assert selected.post(
        "/third-party/executive-reports/reports", json=bad_brand
    ).status_code == 422


def test_static_bearer_is_operator_only_for_report_endpoints(monkeypatch) -> None:
    selected, runtime = client(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "executive-report-secret")
    headers = {"Authorization": "Bearer executive-report-secret"}
    created = selected.post(
        "/third-party/executive-reports/reports",
        headers=headers,
        json={
            "selectors": [],
            "brand": {
                "organization_name": "Lightwork",
                "report_title": "Executive report",
                "footer_text": "Governed record",
                "primary_color": "#102A43",
                "accent_color": "#2CB1BC",
                "text_color": "#243B53",
            },
            "idempotency_key": "create-static-report-0001",
        },
    )
    assert created.status_code == 201
    assert runtime.created is not None
    denied = selected.post(
        "/third-party/executive-reports/maintenance/purge",
        headers=headers,
        json={"limit": 1, "idempotency_key": "purge-static-report-0001"},
    )
    assert denied.status_code == 403
    assert ("purge", None) not in runtime.store.calls


def test_download_token_is_redeemed_in_post_body_and_pdf_is_private(monkeypatch) -> None:
    selected, runtime = client(monkeypatch)
    grant = selected.post(
        "/third-party/executive-reports/reports/report-1/download-grants",
        json={
            "expected_control_revision": 1,
            "idempotency_key": "issue-download-0001",
        },
    )
    assert grant.status_code == 201
    token = grant.json()["token"]
    assert token.startswith("tpr_")
    download = selected.post(
        "/third-party/executive-reports/downloads/redeem",
        json={"token": token},
    )
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/pdf"
    assert download.headers["cache-control"] == "no-store, private, max-age=0"
    assert download.content.startswith(b"%PDF-1.4")
    assert ("redeem", (token, "operator")) in runtime.store.calls


def test_role_gates_and_error_mapping(monkeypatch) -> None:
    selected, _runtime = client(monkeypatch)
    missing = selected.get("/third-party/executive-reports/reports/missing")
    assert missing.status_code == 404
    assert missing.json()["detail"] == "executive_report_not_found"
    monkeypatch.setattr(api, "has_permission", lambda _request, _permission: False)
    denied = selected.post(
        "/third-party/executive-reports/reports",
        json={
            "selectors": [],
            "brand": {
                "organization_name": "Lightwork",
                "report_title": "Executive report",
                "footer_text": "Governed record",
                "primary_color": "#102A43",
                "accent_color": "#2CB1BC",
                "text_color": "#243B53",
            },
            "idempotency_key": "create-report-0002",
        },
    )
    assert denied.status_code == 403
