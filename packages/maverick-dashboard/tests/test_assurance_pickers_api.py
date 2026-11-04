"""Read-only choice lists behind the /security/assurance guided forms."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
BASE = "/api/v1/security/assurance/pickers"
DIGEST = "c" * 64


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config

    config_path = tmp_path / "config.toml"
    config_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    for name in (
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _viewer_only(monkeypatch):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "has_permission", lambda _request, permission: permission == "view")
    monkeypatch.setattr(auth, "has_global_permission", lambda *_args: False)


def test_package_form_fields_come_from_the_server_rules():
    from maverick import ai_bank_mrm, ai_conformity_workflow, ai_regulated_verticals

    response = client.get(f"{BASE}/package-forms")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["regulated"]["nyc_checks"] == list(ai_regulated_verticals.NYC_LL144_CHECKS)
    assert body["regulated"]["naic_checks"] == list(ai_regulated_verticals.NAIC_CHECKS)
    assert [section["key"] for section in body["bank_mrm"]["sections"]] == list(
        ai_bank_mrm._FIELD_SPECS
    )
    tier = next(
        field
        for field in body["bank_mrm"]["sections"][0]["fields"]
        if field["key"] == "model_tier"
    )
    assert tier["kind"] == "choice" and "tier-1" in tier["choices"]
    assert body["conformity"]["checklist_sections"]["fria"] == list(
        ai_conformity_workflow.CHECKLIST_SECTIONS["fria"]
    )
    assert body["insurability"]["measurements"][0] == "evaluation"


def test_package_form_fields_need_the_same_permission_as_the_page(monkeypatch):
    _viewer_only(monkeypatch)

    assert client.get(f"{BASE}/package-forms").status_code == 403


class _Officer:
    finding = {
        "id": "MRF-" + "1" * 24,
        "finding_type": "undeclared_asset",
        "asset_id": "MAA-" + "2" * 32,
        "severity": "high",
        "summary": "The observed AI asset has no accountable human declaration.",
        "finding_sha256": DIGEST,
    }
    acceptance = {
        "id": "MRX-" + "3" * 24,
        "record_kind": "risk_acceptance",
        "finding_id": finding["id"],
        "asset_id": finding["asset_id"],
        "severity": "high",
        "rationale": "Pilot only, reviewed weekly.",
        "reviewer": "user:reviewer",
        "decided_at": 1_800_000_000.0,
        "expires_at": 1_900_000_000.0,
        "status": "accepted",
        "revision": 2,
        "created_at": 1.0,
        "updated_at": 2.0,
    }
    incident = {
        "id": "MRI-" + "4" * 24,
        "asset_id": finding["asset_id"],
        "source_id": "helpdesk-42",
        "severity": "medium",
        "summary": "Assistant gave an out-of-date refund rule.",
        "occurred_at": 1_800_000_100.0,
        "resolution": "",
        "status": "open",
        "revision": 3,
        "created_at": 1.0,
        "updated_at": 2.0,
    }

    def findings(self):
        return [dict(self.finding)]

    def current_risk_acceptance(self, finding):
        return dict(self.acceptance) if finding["id"] == self.finding["id"] else None

    def list_incidents(self):
        return [dict(self.incident)]


def test_records_to_send_need_an_active_workspace(monkeypatch):
    assert client.get(f"{BASE}/grc-sources?source_kind=finding").status_code == 409


@pytest.mark.parametrize("kind", ["finding", "risk_acceptance", "ai_incident"])
def test_records_to_send_are_exact_and_accepted_by_the_send_form(monkeypatch, kind):
    from maverick import grc_outbound_sync
    from maverick_dashboard import assurance_pickers_api, model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    officer = _Officer()
    monkeypatch.setattr(assurance_pickers_api, "_module", lambda *_args: officer)
    monkeypatch.setattr(model_risk_api, "_module", lambda *_args: officer)

    response = client.get(f"{BASE}/grc-sources?source_kind={kind}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["count"] == 1
    row = body["sources"][0]
    record = {"finding": officer.finding, "risk_acceptance": officer.acceptance,
              "ai_incident": officer.incident}[kind]
    assert row["asset_id"] == record["asset_id"]
    assert row["severity"] == record["severity"]
    # The choice is only a reference: the browser never supplies the values
    # that are sent. It is exactly what the preview route accepts ...
    source = row["source"]
    assert source == {"source_kind": kind, "source_id": record["id"]}
    model_risk_api.GRCOutboundSelectionIn.model_validate(source)
    # ... and the server resolves it to the exact current native record.
    resolved, _ = model_risk_api._grc_source(grc_outbound_sync, kind, source["source_id"])
    assert resolved.kind.value == kind and resolved.source_id == record["id"]
    if kind == "finding":
        assert resolved.source_digest == DIGEST and resolved.source_revision == 1
    else:
        assert resolved.source_revision == record["revision"]
        assert len(resolved.source_digest) == 64
        again, _ = model_risk_api._grc_source(grc_outbound_sync, kind, source["source_id"])
        assert again.source_digest == resolved.source_digest


def test_records_to_send_need_the_same_permission_as_the_page(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    _viewer_only(monkeypatch)

    assert client.get(f"{BASE}/grc-sources?source_kind=finding").status_code == 403


def test_case_evidence_needs_an_active_workspace():
    assert client.get(f"{BASE}/conformity-evidence?case_id=EUC-1").status_code == 409


def test_case_evidence_lists_only_the_chosen_case_in_the_workspace(monkeypatch):
    from maverick_dashboard import assurance_pickers_api

    seen = {}

    class Service:
        def list_case_evidence(self, case_id):
            from maverick.paths import current_tenant_id_strict

            seen["tenant"] = current_tenant_id_strict()
            seen["case"] = case_id
            return [{
                "binding_id": "EUE-1",
                "evidence_type": "fria",
                "source_ref": "legal-drive",
                "asset_binding": {},
                "evidence_sha256": DIGEST,
                "binding_sha256": DIGEST,
            }]

    async def configured():
        return None, Service()

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(assurance_pickers_api, "_configured_conformity_workflow", configured)

    response = client.get(f"{BASE}/conformity-evidence?case_id=EUC-1")

    assert response.status_code == 200, response.text
    assert response.json()["evidence"] == [
        {"binding_id": "EUE-1", "evidence_type": "fria", "source_ref": "legal-drive"}
    ]
    assert seen == {"tenant": "alpha", "case": "EUC-1"}


class _Registry:
    def __init__(self):
        self.kinds = []

    def active_payloads(self, kind):
        self.kinds.append(kind)
        return {
            "federation_binding": [{
                "provider": "okta",
                "principal_ref": "prn_" + "5" * 32,
                "provider_subject_id": "sub_" + "6" * 32,
                "binding_sha256": DIGEST,
                "authority_revision": 2,
            }],
            "purview_asset_binding": [{
                "asset_id": "ast_" + "7" * 32,
                "binding_sha256": DIGEST,
                "revision": 4,
                "classification_codes": ["confidential"],
            }],
            "capability_rule": [{"capabilities": ["agent.execute"]}],
        }[kind]


def test_agent_identity_choices_are_for_administrators_only(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    _viewer_only(monkeypatch)

    assert client.get(f"{BASE}/identity-controls").status_code == 403


def test_agent_identity_choices_need_an_active_workspace():
    assert client.get(f"{BASE}/identity-controls").status_code == 409


def test_agent_identity_choices_come_from_the_workspace_registry(monkeypatch):
    from maverick_dashboard import assurance_pickers_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(assurance_pickers_api, "_human_principal", lambda _request: "user:admin")
    registry = _Registry()
    calls = []

    def factory(tenant_id):
        calls.append(tenant_id)
        return registry

    monkeypatch.setattr(
        app.state, "identity_governance_authority_registry_factory", factory, raising=False
    )

    response = client.get(f"{BASE}/identity-controls")

    assert response.status_code == 200, response.text
    body = response.json()
    assert calls == ["alpha"]
    assert body["available"] is True
    assert body["capabilities"] == ["agent.execute"]
    assert body["federation_bindings"][0]["authority_revision"] == 2
    assert body["purview_assets"][0]["revision"] == 4
    # Prepared changes are listed only when the change control is turned on.
    assert body["purview_intents"] == [] and body["purview_intents_available"] is False
    # Labels to tick come from the enrolled data; Purview is not connected here.
    assert body["purview_labels"] == ["confidential"]
    assert body["purview_connected"] is False


def test_agent_identity_choices_are_empty_without_an_enrolment_registry(monkeypatch):
    from maverick_dashboard import assurance_pickers_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(assurance_pickers_api, "_human_principal", lambda _request: "user:admin")
    monkeypatch.setattr(
        app.state, "identity_governance_authority_registry_factory", None, raising=False
    )

    body = client.get(f"{BASE}/identity-controls").json()

    assert body["available"] is False
    assert body["federation_bindings"] == [] and body["purview_assets"] == []


def test_purview_labels_merge_enrolled_data_and_prepared_changes(monkeypatch):
    from maverick_dashboard import assurance_pickers_api, identity_governance_runtime

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(assurance_pickers_api, "_human_principal", lambda _request: "user:admin")
    monkeypatch.setattr(
        app.state,
        "identity_governance_authority_registry_factory",
        lambda _tenant: _Registry(),
        raising=False,
    )

    class Writeback:
        def list_intents(self, *, limit):
            return [
                {"intent_id": "IGPW-" + "8" * 32, "classification_codes": ["regulated", "Not A Code"]},
                {"intent_id": "IGPW-" + "9" * 32, "classification_codes": ["confidential"]},
            ]

    class Runtime:
        def require_purview_writeback(self):
            return Writeback()

    monkeypatch.setattr(assurance_pickers_api, "_identity_governance_section", lambda: {"enable": True})
    monkeypatch.setattr(assurance_pickers_api, "_identity_control_runtime", lambda *_args: Runtime())
    monkeypatch.setattr(
        identity_governance_runtime,
        "connector_status",
        lambda _section: {"configured_providers": ["okta", "purview"]},
    )

    body = client.get(f"{BASE}/identity-controls").json()

    assert body["purview_intents_available"] is True
    # Only well-formed label codes are offered, each once, in order.
    assert body["purview_labels"] == ["confidential", "regulated"]
    assert body["purview_connected"] is True


def test_legal_provisions_come_from_the_kernel_catalogs_and_are_all_citable():
    from maverick import ai_conformity_workflow as conformity
    from maverick import eu_conformity

    response = client.get(f"{BASE}/legal-provisions")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["default_official_url"] == conformity.CONSOLIDATED_REGULATION_URL
    rows = body["provisions"]
    assert body["count"] == len(rows) and 0 < len(rows) <= 500
    by_key = {(row["regulation"], row["provision"]): row for row in rows}
    fria = by_key[("EU AI Act", eu_conformity.FRIA_ELEMENTS["process_description"]["citation"])]
    assert fria["official_url"] == conformity.CONSOLIDATED_REGULATION_URL
    assert fria["title"].startswith("The deployer's processes")
    assert ("EU AI Act", "Annex III point 4") in by_key
    assert ("EU AI Act", "Art. 5(1)(h)") in by_key
    gdpr = by_key[("GDPR", "Art. 35")]
    assert gdpr["official_url"].startswith("https://eur-lex.europa.eu/eli/reg/2016/679")
    # Every offered provision is accepted by the readiness workflow as is.
    for row in rows:
        conformity._citation(conformity.LegalCitation(row["provision"], row["official_url"]))
    regulations = [row["regulation"] for row in rows]
    assert regulations == sorted(regulations, key=lambda name: name != "EU AI Act")


def test_legal_provisions_need_the_same_permission_as_the_forms(monkeypatch):
    _viewer_only(monkeypatch)

    assert client.get(f"{BASE}/legal-provisions").status_code == 403


def test_release_references_need_an_active_workspace():
    assert client.get(f"{BASE}/media-release-references").status_code == 409


def test_release_references_need_the_media_records_permission(monkeypatch):
    from maverick_dashboard import auth

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(auth, "has_permission", lambda *_args: False)
    monkeypatch.setattr(auth, "has_global_permission", lambda *_args: False)

    assert client.get(f"{BASE}/media-release-references").status_code == 403


def test_release_references_list_only_the_active_workspace(monkeypatch):
    from maverick_dashboard import assurance_pickers_api

    seen = {}
    row = {
        "context_id": "spring-campaign-2026",
        "last_used_at": 1_800_000_000.0,
        "deployment_ids": ["production-east"],
        "record_count": 2,
    }

    class Service:
        def release_references(self, *, limit):
            from maverick.paths import current_tenant_id_strict

            seen["tenant"] = current_tenant_id_strict()
            seen["limit"] = limit
            return [dict(row)]

    async def configured():
        return None, Service()

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    _viewer_only(monkeypatch)
    monkeypatch.setattr(assurance_pickers_api, "_configured_media_provenance", configured)

    response = client.get(f"{BASE}/media-release-references")

    assert response.status_code == 200, response.text
    assert response.json() == {"references": [row], "count": 1}
    assert seen == {"tenant": "alpha", "limit": 200}


def test_release_references_read_the_real_store_without_a_release_authority(tmp_path, monkeypatch):
    from maverick import config

    (tmp_path / "config.toml").write_text(
        "[ai_media_provenance]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")

    # Listing only reads stored records, so it works before any release system
    # is connected; checking and signing still need that connection.
    assert client.get(f"{BASE}/media-release-references").json() == {
        "references": [],
        "count": 0,
    }
