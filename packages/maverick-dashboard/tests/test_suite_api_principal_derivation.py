"""Cross-suite regression test for suite-API principal derivation.

29 dashboard suite-API modules each copied a `_principal`/`_principal_ref`
helper that 401'd whenever `request.state.principal` was empty -- but that's
also true for two ALREADY-authenticated shapes `require_permission` itself
accepts: a valid static `MAVERICK_DASHBOARD_TOKEN` bearer, and genuine local
single-user auth-off mode. So the documented static-token API path and
single-user local mode couldn't use most of these suites at all, while a
handful of others (which happened to implement the same three-way check
themselves) worked fine.

This drives the REAL app through the REAL auth stack (`auth.py`), not a
bespoke per-file fake, so it actually exercises the bug: a per-tool test
that only calls a module's own `_run`/route function directly can't see a
gap in how `request.state.principal` gets derived in the first place.

One status/readiness route per fixed suite, parametrized over both
previously-broken caller shapes. The universal, correct assertion is "never
401" -- not "always 200": a suite can legitimately answer 403/503 for an
unrelated reason (its own feature disabled, unconfigured backend) in this
bare test environment, and that's not what this fix is about.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

TENANT = "tenant-w3-1-probe"
STATIC_TOKEN = "w3-1-probe-static-token"  # noqa: S105 - test fixture value, not a real secret

#: (module, route) for every suite fixed. One representative
#: read-only route per module -- its own status/readiness endpoint, since
#: every one of these was gated by the same broken helper.
ROUTES = [
    ("ai_entity_tasks_api", "/api/v1/ai-entity-tasks/status"),
    ("compliance_scope_actions_api", "/api/v1/compliance/scope-actions/status"),
    ("compliance_scoping_api", "/api/v1/compliance/scoping/status"),
    ("consent_application_scanner_api", "/api/v1/consent/application-scans/readiness"),
    ("consent_custom_index_api", "/api/v1/consent/custom-indexes/status"),
    ("consent_global_opt_out_api", "/api/v1/consent/global-opt-out/status"),
    ("consent_scan_notice_proposals_api", "/api/v1/consent/scan-notice-proposals/status"),
    ("consumer_trust_center_authority_api", "/api/v1/consent/trust-center-authority/status"),
    ("data_use_provider_audit_api", "/api/v1/data-use/providers/audit/status"),
    ("governance_agents_api", "/api/v1/governance-agents/status"),
    ("incident_attachment_metadata_api", "/api/v1/incident-attachments/status"),
    ("privacy_drop_management_api", "/api/v1/privacy/drop/status"),
    ("privacy_notice_governance_api", "/api/v1/privacy/notices/status"),
    ("privacy_rights_consumer_delivery_api", "/api/v1/privacy/rights-consumer-delivery/status"),
    ("privacy_rights_orchestration_api", "/api/v1/privacy/rights-orchestration/status"),
    ("third_party_collaboration_api", "/api/v1/third-party/collaboration/status"),
    ("third_party_lifecycle_api", "/api/v1/third-party/lifecycle/status"),
    ("trc_continuous_evidence_api", "/api/v1/compliance/continuous-evidence/status"),
    ("trust_center_branding_api", "/api/v1/consent/trust-center-branding/status"),
    ("ai_evidence_analysis_api", "/api/v1/ai-evidence-analysis/status"),
    ("consent_web_publish_settings_api", "/api/v1/consent/publish-settings/status"),
    ("no_code_grc_studio_api", "/api/v1/compliance/grc-studio/status"),
    ("third_party_contracts_api", "/api/v1/third-party/contracts/status"),
    ("consent_native_admin_api", "/api/v1/consent/native/readiness"),
    # privacy_drop_authority_api has no status/readiness route of its own --
    # it shares privacy_drop_management_api's digest namespace and gate
    # shape, and is covered by that module's route here.
]


@pytest.fixture(autouse=True)
def _isolated_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", TENANT)


@pytest.mark.parametrize("module, route", ROUTES, ids=[m for m, _ in ROUTES])
def test_suite_status_route_accepts_a_valid_static_bearer(
    module: str, route: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", STATIC_TOKEN)
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={
            "Origin": "http://127.0.0.1",
            "Authorization": f"Bearer {STATIC_TOKEN}",
        },
    )
    response = client.get(route)
    assert response.status_code != 401, (
        f"{module} {route}: a valid static MAVERICK_DASHBOARD_TOKEN bearer must "
        f"not 401 (got {response.status_code}: {response.text[:300]})"
    )


@pytest.mark.parametrize("module, route", ROUTES, ids=[m for m, _ in ROUTES])
def test_suite_status_route_accepts_genuine_local_auth_off(
    module: str, route: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick_dashboard.auth.anonymous_local_access_allowed", lambda: True)
    monkeypatch.setattr("maverick_dashboard.auth._dashboard_token_authenticated", lambda _r: False)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.get(route)
    assert response.status_code != 401, (
        f"{module} {route}: genuine local auth-off mode must not 401 "
        f"(got {response.status_code}: {response.text[:300]})"
    )


@pytest.mark.parametrize("module, route", ROUTES, ids=[m for m, _ in ROUTES])
def test_suite_status_route_still_401s_with_no_authentication_at_all(
    module: str, route: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative control: principal derivation widens who counts as
    authenticated -- it must not become allow-all. A caller that is genuinely neither a named
    principal, nor a valid static bearer, nor in real auth-off mode is still
    refused."""
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick_dashboard.auth.anonymous_local_access_allowed", lambda: False)
    monkeypatch.setattr("maverick_dashboard.auth._dashboard_token_authenticated", lambda _r: False)
    monkeypatch.setattr("maverick_dashboard.auth.oidc_enabled", lambda: False)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.get(route)
    assert response.status_code == 401, (
        f"{module} {route}: a genuinely unauthenticated caller must still 401 "
        f"(got {response.status_code}: {response.text[:300]})"
    )
