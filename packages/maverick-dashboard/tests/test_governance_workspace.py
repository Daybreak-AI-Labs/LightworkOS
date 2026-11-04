"""HTTP acceptance for the governance workspace: the /security/governance
page and the /api/v1/security/governance router (FRIA, Annex IV, AI
literacy, GRC sync visibility) plus the Art. 73 mutation routes on the
assurance router. The audience is legal/privacy/compliance staff, so the
page tests also assert the plain-language disabled-state guidance.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

_BASE_CONFIG = """[evidence_graph]
enable = true

[model_risk_assurance]
enable = true
gate_promotions = false
"""

_GOVERNANCE_CONFIG = """
[eu_conformity]
enable = true

[ai_literacy]
enable = true

[ai_incident_reporting]
enable = true

[grc_sync]
enable = true
incidents_path = "/api/now/table/incident"
"""


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import audit, config, world_model
    from maverick.audit import writer as audit_writer

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config_path = tmp_path / "config.toml"
    config_path.write_text(_BASE_CONFIG, encoding="utf-8")
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
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    yield
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()


def _ok(response, expected=200):
    assert response.status_code == expected, response.text
    return response.json()


def _reset_config_with(extra: str) -> None:
    from maverick import config

    path = Path(config.config_path())
    path.write_text(_BASE_CONFIG + extra, encoding="utf-8")
    config.reset_config_cache()


def _enable_governance() -> None:
    _reset_config_with(_GOVERNANCE_CONFIG)


_PREFIX = "/api/v1/security/governance"
_ASSURANCE = "/api/v1/security/assurance"

# A fake ServiceNow sys_id returned by the stubbed GRC writer.
_FAKE_SYS_ID = "abc123def456"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Fail-closed wiring and the disabled-state page
# ---------------------------------------------------------------------------

def test_disabled_modules_fail_closed_and_page_offers_controls():
    for path in (
        f"{_PREFIX}/fria",
        f"{_PREFIX}/literacy/gaps",
        f"{_PREFIX}/grc-sync/status",
    ):
        assert client.get(path).status_code == 403, path
    assert client.post(
        f"{_PREFIX}/fria",
        json={"asset_id": "MAA-" + "0" * 32, "context": "triage"},
    ).status_code == 403

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert "AI governance" in page.text
    assert "EU AI Act workflows is turned off" in page.text
    assert "Staff AI training tracking is turned off" in page.text
    assert "Serious-incident reporting is turned off" in page.text
    assert page.text.count('data-module-gate="eu_conformity"') == 6
    assert page.text.count('data-module-gate="ai_literacy"') == 1
    assert page.text.count('data-module-gate="ai_incident_reporting"') == 1
    assert page.text.count('class="btn btn--primary mg-on"') >= 8
    assert "setup wizard" not in page.text.lower()
    assert "is not set up" in page.text
    # Config section names are never shown to people.
    assert "[eu_conformity]" not in page.text and "[ai_literacy]" not in page.text


def test_governance_turn_on_controls_open_their_sections():
    for section in ("eu_conformity", "ai_literacy", "ai_incident_reporting"):
        enabled = client.post("/api/v1/features/modules", json={
            "section": section, "enabled": True,
        })
        assert enabled.status_code == 200, (section, enabled.text)
    page = client.get("/security/governance")
    assert page.status_code == 200, page.text
    for section in ("eu_conformity", "ai_literacy", "ai_incident_reporting"):
        assert f'data-module-gate="{section}"' not in page.text
    assert 'id="fria-open"' in page.text
    assert 'id="literacy-require"' in page.text
    assert 'id="incident-declare"' in page.text


def test_governance_page_is_registered_for_the_sidebar():
    from maverick_dashboard import ui_visibility

    page = ui_visibility.page_for("/security/governance")
    assert page is not None and page["path"] == "/security/governance"
    assert page["floor"] == "operate"
    assert page.get("in_nav", True) is True


# ---------------------------------------------------------------------------
# FRIA (Art. 27) end to end through the HTTP surface
# ---------------------------------------------------------------------------

def test_fria_lifecycle_through_the_api_and_page():
    _enable_governance()
    asset_id = "MAA-" + _hex("underwriting-model")[:32]

    opened = _ok(
        client.post(
            f"{_PREFIX}/fria",
            json={"asset_id": asset_id, "context": "underwriting-triage"},
        ),
        expected=201,
    )
    assert opened["status"] == "draft"
    assert set(opened["elements"]) == {
        "process_description",
        "period_frequency",
        "affected_categories",
        "risks_of_harm",
        "oversight_measures",
        "materialisation_measures",
    }

    # Reopening the same asset/context returns the same governed record.
    again = _ok(
        client.post(
            f"{_PREFIX}/fria",
            json={"asset_id": asset_id, "context": "underwriting-triage"},
        ),
        expected=201,
    )
    assert again["id"] == opened["id"]

    listing = _ok(client.get(f"{_PREFIX}/fria"))
    assert listing["count"] == 1
    assert "process_description" in listing["elements"]

    # The editor's operate-floor record fetch carries the answer bodies.
    fetched = _ok(client.get(f"{_PREFIX}/fria/{opened['id']}"))
    assert fetched["record"]["id"] == opened["id"]
    assert client.get(f"{_PREFIX}/fria/ECF-{'0' * 24}").status_code == 404

    # An element outside Art. 27(1) is refused before any write.
    assert client.post(
        f"{_PREFIX}/fria/{opened['id']}/elements",
        json={"element": "nope", "content": "x", "expected_revision": 1},
    ).status_code == 422

    revision = opened["revision"]
    for element in opened["elements"]:
        saved = _ok(
            client.post(
                f"{_PREFIX}/fria/{opened['id']}/elements",
                json={
                    "element": element,
                    "content": f"Answer for {element} written by counsel.",
                    "expected_revision": revision,
                },
            )
        )
        revision = saved["revision"]

    # A stale revision conflicts instead of silently overwriting.
    assert client.post(
        f"{_PREFIX}/fria/{opened['id']}/complete",
        json={"expected_revision": 1},
    ).status_code == 409

    completed = _ok(
        client.post(
            f"{_PREFIX}/fria/{opened['id']}/complete",
            json={"expected_revision": revision},
        )
    )
    assert completed["status"] == "completed"
    assert completed["assessor"] == "local:dashboard"

    assert _ok(
        client.get(f"{_PREFIX}/fria", params={"status": "completed"})
    )["count"] == 1

    draft = _ok(client.get(f"{_PREFIX}/fria/{opened['id']}/draft"))
    assert "Art. 27(1)(a)" in draft["draft"]
    assert "Answer for oversight_measures" in draft["draft"]

    notified = _ok(
        client.post(
            f"{_PREFIX}/fria/{opened['id']}/notification",
            json={
                "authority": "Market surveillance authority",
                "reference": "MSA-2026-0042",
                "submitted_at": time.time(),
                "expected_revision": completed["revision"],
            },
        )
    )
    assert notified["notification"]["reference"] == "MSA-2026-0042"

    outdated = _ok(
        client.post(
            f"{_PREFIX}/fria/{opened['id']}/outdate",
            json={
                "reason": "The deployment context changed to a new market.",
                "expected_revision": notified["revision"],
            },
        )
    )
    assert outdated["status"] == "outdated"

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert opened["id"] in page.text
    assert "6 of 6 questions answered" in page.text
    assert "Work on it" in page.text


def test_fria_request_schema_is_closed():
    _enable_governance()
    assert client.post(
        f"{_PREFIX}/fria",
        json={
            "asset_id": "MAA-" + "0" * 32,
            "context": "triage",
            "extra": "nope",
        },
    ).status_code == 422
    assert client.post(
        f"{_PREFIX}/fria",
        json={"asset_id": "not-an-asset", "context": "triage"},
    ).status_code == 422


# ---------------------------------------------------------------------------
# Annex IV checklist (Art. 11(1))
# ---------------------------------------------------------------------------

def test_annex_iv_checklist_through_the_api():
    _enable_governance()
    asset_id = "MAA-" + _hex("credit-model")[:32]

    opened = _ok(
        client.post(f"{_PREFIX}/annex-iv", json={"asset_id": asset_id}),
        expected=201,
    )
    record = opened["record"]
    assert opened["status"]["total"] == 9
    assert opened["status"]["asserted"] == 0
    assert "general_description" in opened["items"]

    state = _ok(
        client.post(
            f"{_PREFIX}/annex-iv/{record['id']}/items",
            json={
                "item": "general_description",
                "reference": "wiki/models/credit#overview",
                "expected_revision": record["revision"],
            },
        )
    )
    assert state["asserted"] == 1
    assert "general_description" not in state["missing"]

    fetched = _ok(client.get(f"{_PREFIX}/annex-iv/{record['id']}"))
    assert fetched["status"]["asserted"] == 1

    rendered = _ok(client.get(f"{_PREFIX}/annex-iv/{record['id']}/render"))
    assert "Annex IV(1)" in rendered["rendered"]

    assert client.get(f"{_PREFIX}/annex-iv/ECD-{'0' * 24}").status_code == 404
    assert client.post(
        f"{_PREFIX}/annex-iv/{record['id']}/items",
        json={
            "item": "not-an-item",
            "reference": "wiki",
            "expected_revision": state["revision"],
        },
    ).status_code == 422


# ---------------------------------------------------------------------------
# Art. 43 conformity-assessment routes
# ---------------------------------------------------------------------------

def test_art43_route_lifecycle_through_the_api_and_page():
    _enable_governance()
    asset_id = "MAA-" + _hex("triage-router")[:32]

    # Art. 43(1): a point-1 system without standards cannot self-assess.
    refused = client.post(
        f"{_PREFIX}/routes",
        json={
            "asset_id": asset_id,
            "route": "internal_control_annex_vi",
            "annex_iii_point": 1,
            "rationale": "Biometric triage without harmonised standards.",
        },
    )
    assert refused.status_code == 409
    assert "Art. 43(1)" in refused.json()["detail"]

    # Art. 43(2): points 2-8 never involve a notified body.
    refused = client.post(
        f"{_PREFIX}/routes",
        json={
            "asset_id": asset_id,
            "route": "notified_body_annex_vii",
            "annex_iii_point": 4,
            "rationale": "Point 4 with a notified body.",
        },
    )
    assert refused.status_code == 409
    assert "Art. 43(2)" in refused.json()["detail"]

    # A sectoral route carries no Annex III point.
    assert client.post(
        f"{_PREFIX}/routes",
        json={
            "asset_id": asset_id,
            "route": "sectoral_annex_i",
            "annex_iii_point": 3,
            "rationale": "Sectoral with a point.",
        },
    ).status_code == 422

    recorded = _ok(
        client.post(
            f"{_PREFIX}/routes",
            json={
                "asset_id": asset_id,
                "route": "internal_control_annex_vi",
                "annex_iii_point": 4,
                "harmonised_standards_applied": True,
                "rationale": "Point 4 internal control under harmonised standards.",
            },
        ),
        expected=201,
    )
    assert recorded["status"] == "recorded"
    assert recorded["decided_by"] == "local:dashboard"

    # A second decision for the same asset conflicts instead of overwriting.
    assert client.post(
        f"{_PREFIX}/routes",
        json={
            "asset_id": asset_id,
            "route": "internal_control_annex_vi",
            "annex_iii_point": 4,
            "rationale": "Recorded twice.",
        },
    ).status_code == 409

    fetched = _ok(client.get(f"{_PREFIX}/routes/{asset_id}"))
    assert fetched["record"]["route"] == "internal_control_annex_vi"
    assert client.get(f"{_PREFIX}/routes/MAA-{'0' * 32}").status_code == 404

    listing = _ok(client.get(f"{_PREFIX}/routes"))
    assert listing["count"] == 1
    assert "internal_control_annex_vi" in listing["routes"]

    modified = _ok(
        client.post(
            f"{_PREFIX}/routes/{asset_id}/modification",
            json={
                "reason": "The system now serves a new user population.",
                "expected_revision": fetched["record"]["revision"],
            },
        )
    )
    assert modified["status"] == "reassessment_required"
    assert client.post(
        f"{_PREFIX}/routes/MAA-{'0' * 32}/modification",
        json={"reason": "Missing asset.", "expected_revision": 1},
    ).status_code == 404

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert "Approval route before launch" in page.text
    assert "Needs a new assessment" in page.text
    assert "data-route-change=" in page.text


# ---------------------------------------------------------------------------
# Role boundaries: a viewer reads, never writes
# ---------------------------------------------------------------------------

def test_viewer_role_reads_but_never_mutates(monkeypatch):
    from maverick_dashboard import auth

    _enable_governance()
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:paralegal")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "viewer")

    assert client.get(f"{_PREFIX}/routes").status_code == 200
    assert client.get(f"{_PREFIX}/literacy/gaps").status_code == 200
    assert client.get(f"{_PREFIX}/grc-sync/status").status_code == 200
    assert client.get(f"{_PREFIX}/pmm").status_code == 200
    assert client.get(f"{_PREFIX}/registrations").status_code == 200
    assert client.get(f"{_PREFIX}/alerts").status_code == 200

    # The view-floor FRIA listing never carries answer bodies; the full
    # record (and therefore the content) is operate-floor.
    opened = None
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "operator")
    opened = client.post(
        f"{_PREFIX}/fria",
        json={"asset_id": "MAA-" + "1" * 32, "context": "triage"},
    ).json()
    client.post(
        f"{_PREFIX}/fria/{opened['id']}/elements",
        json={
            "element": "process_description",
            "content": "A privileged answer body.",
            "expected_revision": opened["revision"],
        },
    )
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "viewer")
    listing = client.get(f"{_PREFIX}/fria")
    assert listing.status_code == 200
    assert "A privileged answer body." not in listing.text
    row = listing.json()["records"][0]
    assert row["elements"]["process_description"]["asserted"] is True
    assert client.get(f"{_PREFIX}/fria/{opened['id']}").status_code == 403

    mutations = (
        (f"{_PREFIX}/fria", {"asset_id": "MAA-" + "0" * 32, "context": "x"}),
        (
            f"{_PREFIX}/routes",
            {
                "asset_id": "MAA-" + "0" * 32,
                "route": "sectoral_annex_i",
                "rationale": "viewer attempt",
            },
        ),
        (
            f"{_PREFIX}/literacy/assignments",
            {"person": "someone", "roles": ["role"], "expected_revision": 0},
        ),
    )
    for path, body in mutations:
        assert client.post(path, json=body).status_code == 403, path
    # The evidence export and the workspace page itself are operate-floor.
    assert client.get(f"{_PREFIX}/literacy/evidence").status_code == 403
    assert client.get("/security/governance").status_code == 403


# ---------------------------------------------------------------------------
# Market obligations: Art. 72 / Art. 49 / Art. 13
# ---------------------------------------------------------------------------

def test_market_obligations_through_the_api_and_page():
    _enable_governance()
    asset_id = "MAA-" + _hex("market-model")[:32]

    plan = _ok(
        client.post(
            f"{_PREFIX}/pmm",
            json={"asset_id": asset_id, "plan_reference": "wiki/models/pmm-plan"},
        ),
        expected=201,
    )
    assert plan["citation"] == "Art. 72(1)"
    # A second plan for the same asset conflicts instead of overwriting.
    assert client.post(
        f"{_PREFIX}/pmm",
        json={"asset_id": asset_id, "plan_reference": "wiki/other"},
    ).status_code == 409

    reviewed = _ok(
        client.post(
            f"{_PREFIX}/pmm/{asset_id}/review",
            json={
                "outcome": "plan_updated",
                "plan_reference": "wiki/models/pmm-plan-v2",
                "expected_revision": plan["revision"],
            },
        )
    )
    assert reviewed["plan_reference"] == "wiki/models/pmm-plan-v2"
    assert client.post(
        f"{_PREFIX}/pmm/MAA-{'0' * 32}/review",
        json={"outcome": "no_change", "expected_revision": 1},
    ).status_code == 404

    # The wrong registry for a basis is refused with its citation.
    refused = client.post(
        f"{_PREFIX}/registrations",
        json={
            "asset_id": asset_id,
            "basis": "provider_high_risk",
            "registry": "national",
            "reference": "NAT-1",
        },
    )
    assert refused.status_code == 409
    assert "Art. 49(1)" in refused.json()["detail"]
    registered = _ok(
        client.post(
            f"{_PREFIX}/registrations",
            json={
                "asset_id": asset_id,
                "basis": "provider_high_risk",
                "registry": "eu_database",
                "reference": "EUDB-2026-17",
            },
        ),
        expected=201,
    )
    assert registered["citation"] == "Art. 49(1)"

    opened = _ok(
        client.post(f"{_PREFIX}/ifu", json={"asset_id": asset_id}),
        expected=201,
    )
    assert opened["status"]["total"] == 6
    state = _ok(
        client.post(
            f"{_PREFIX}/ifu/{opened['record']['id']}/items",
            json={
                "item": "provider_identity",
                "reference": "handbook#provider",
                "expected_revision": opened["record"]["revision"],
            },
        )
    )
    assert state["asserted"] == 1
    fetched = _ok(client.get(f"{_PREFIX}/ifu/{opened['record']['id']}"))
    assert fetched["status"]["missing"] != []
    assert client.get(f"{_PREFIX}/ifu/ECI-{'0' * 24}").status_code == 404

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert "Monitoring plan" in page.text
    assert "wiki/models/pmm-plan-v2" in page.text
    assert "EUDB-2026-17" in page.text
    assert "Instructions for use" in page.text
    assert "Download all records" in page.text
    assert "data-pmm-review=" in page.text


# ---------------------------------------------------------------------------
# The per-asset audit bundle
# ---------------------------------------------------------------------------

def test_audit_bundle_collects_every_register():
    _enable_governance()
    incident = _assurance_incident()
    from maverick import ai_incident_reporting as air
    from maverick import model_risk_assurance as mra

    asset_id = next(
        row["asset_id"] for row in mra.list_incidents()
        if row["id"] == incident["id"]
    )

    opened = _ok(
        client.post(
            f"{_PREFIX}/fria",
            json={"asset_id": asset_id, "context": "triage"},
        ),
        expected=201,
    )
    _ok(
        client.post(
            f"{_PREFIX}/fria/{opened['id']}/elements",
            json={
                "element": "process_description",
                "content": "Counsel's process answer.",
                "expected_revision": opened["revision"],
            },
        )
    )
    annex = _ok(
        client.post(f"{_PREFIX}/annex-iv", json={"asset_id": asset_id}),
        expected=201,
    )
    _ok(
        client.post(
            f"{_PREFIX}/routes",
            json={
                "asset_id": asset_id,
                "route": "internal_control_annex_vi",
                "annex_iii_point": 4,
                "harmonised_standards_applied": True,
                "rationale": "Point 4 internal control.",
            },
        ),
        expected=201,
    )
    _ok(
        client.post(
            f"{_PREFIX}/pmm",
            json={"asset_id": asset_id, "plan_reference": "wiki/pmm"},
        ),
        expected=201,
    )
    air.declare_serious_incident(
        incident["id"],
        category="critical_infrastructure_disruption",
        became_aware_at=time.time() - 3_600,
        causal_link="reasonably_likely",
        member_state="DE",
        authority="Bundesnetzagentur market surveillance",
        declared_by="incident-manager",
    )

    bundle = _ok(client.get(f"{_PREFIX}/bundle/{asset_id}"))
    sections = bundle["sections"]
    assert sections["fria"][0]["id"] == opened["id"]
    assert "Art. 27" in sections["fria"][0]["draft"]
    assert sections["annex_iv"]["status"]["id"] == annex["record"]["id"]
    assert sections["assessment_route"]["route"] == "internal_control_annex_vi"
    assert sections["pmm_plan"]["plan_reference"] == "wiki/pmm"
    assert sections["registration"] is None
    assert sections["instructions_for_use"] is None
    declarations = sections["serious_incidents"]["declarations"]
    assert len(declarations) == 1
    assert "Art. 73" in declarations[0]["report_draft"]
    assert bundle["notice"]


# ---------------------------------------------------------------------------
# The needs-attention digest
# ---------------------------------------------------------------------------

def test_needs_attention_digest_on_api_and_page():
    _enable_governance()
    incident = _assurance_incident(occurred_at=time.time() - 30 * 86_400)
    from maverick import ai_incident_reporting as air

    quiet = _ok(client.get(f"{_PREFIX}/alerts"))
    assert quiet["attention_count"] == 0

    air.declare_serious_incident(
        incident["id"],
        category="critical_infrastructure_disruption",
        became_aware_at=time.time() - 20 * 86_400,
        causal_link="under_investigation",
        member_state="DE",
        authority="Bundesnetzagentur market surveillance",
        declared_by="incident-manager",
    )
    _ok(
        client.post(
            f"{_PREFIX}/literacy/requirements",
            json={
                "role": "operator",
                "trainings": [
                    {"key": "ai-fundamentals", "title": "AI fundamentals",
                     "validity_days": None},
                ],
                "expected_revision": 0,
            },
        )
    )
    _ok(
        client.post(
            f"{_PREFIX}/literacy/assignments",
            json={
                "person": "analyst@example.com",
                "roles": ["operator"],
                "expected_revision": 0,
            },
        )
    )

    digest = _ok(client.get(f"{_PREFIX}/alerts"))
    assert digest["attention_count"] == 3
    assert len(digest["sections"]["serious_incidents"]["overdue"]) == 1
    assert digest["sections"]["ai_literacy"]["missing"] == 1
    assert digest["sections"]["ai_literacy"][
        "unreconciled_ai_literacy_data"
    ] is True

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert "Needs attention" in page.text
    assert re.search(r"\d+ incident reports? overdue", page.text)
    assert re.search(r"\d+ trainings? not done", page.text)
    # The alerts stand on their own; the CLI that mirrors them is not shown
    # to a non-technical user.
    assert "governance-alerts due" not in page.text


# ---------------------------------------------------------------------------
# GPAI provider obligations and four-eyes review
# ---------------------------------------------------------------------------

def test_gpai_register_through_the_api():
    _enable_governance()
    asset_id = "MAA-" + _hex("gpai-model")[:32]

    refused = client.post(
        f"{_PREFIX}/gpai",
        json={
            "asset_id": asset_id,
            "systemic_risk": True,
            "open_source_exempt": True,
        },
    )
    assert refused.status_code == 409
    assert "Art. 53(2)" in refused.json()["detail"]

    opened = _ok(
        client.post(
            f"{_PREFIX}/gpai",
            json={"asset_id": asset_id, "systemic_risk": True},
        ),
        expected=201,
    )
    assert opened["status"]["total"] == 8

    state = _ok(
        client.post(
            f"{_PREFIX}/gpai/{opened['record']['id']}/obligations",
            json={
                "obligation": "model_evaluation",
                "reference": "eval-vault#adversarial-2026Q3",
                "expected_revision": opened["record"]["revision"],
            },
        )
    )
    assert state["asserted"] == 1
    listing = _ok(client.get(f"{_PREFIX}/gpai"))
    assert listing["count"] == 1
    assert "technical_documentation" in listing["obligations"]
    fetched = _ok(client.get(f"{_PREFIX}/gpai/{opened['record']['id']}"))
    assert fetched["status"]["systemic_risk"] is True
    assert client.get(f"{_PREFIX}/gpai/ECG-{'0' * 24}").status_code == 404


def test_fria_review_is_four_eyes_gated():
    _enable_governance()
    asset_id = "MAA-" + _hex("review-model")[:32]
    opened = _ok(
        client.post(
            f"{_PREFIX}/fria",
            json={"asset_id": asset_id, "context": "triage"},
        ),
        expected=201,
    )
    record = opened
    for element in (
        "process_description", "period_frequency", "affected_categories",
        "risks_of_harm", "oversight_measures", "materialisation_measures",
    ):
        record = _ok(
            client.post(
                f"{_PREFIX}/fria/{opened['id']}/elements",
                json={
                    "element": element,
                    "content": f"Assessed: {element}.",
                    "expected_revision": record["revision"],
                },
            )
        )
    completed = _ok(
        client.post(
            f"{_PREFIX}/fria/{opened['id']}/complete",
            json={"expected_revision": record["revision"]},
        )
    )
    # The dashboard actor completed the assessment, so the same actor's
    # review must be refused (four-eyes).
    denied = client.post(
        f"{_PREFIX}/fria/{opened['id']}/review",
        json={"outcome": "concur", "expected_revision": completed["revision"]},
    )
    assert denied.status_code == 409
    assert "other than the assessor" in denied.json()["detail"]


def test_page_speaks_plainly_and_uses_in_page_dialogs():
    _enable_governance()
    _assurance_incident()
    page = client.get("/security/governance")
    assert page.status_code == 200
    main = page.text.split('<main id="content"', 1)[1].split("</main>", 1)[0]
    script = main[main.index('<script nonce="'):]
    visible = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", " ", main)
    assert not re.search(
        r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
        r"MAA-[0-9a-f]|MRI-[0-9a-f]|GPAI|FRIA|UNASSIGNED|OVERDUE)\b|/api/v1|\[eu_conformity\]",
        visible,
    ), visible
    assert "window.prompt" not in script
    assert "window.location.reload()" in script  # tables refresh; the message survives via done()
    assert "mvForm" in script
    assert 'id="agent-check"' in page.text and 'id="agent-lineage"' in page.text


# ---------------------------------------------------------------------------
# Pickers: nobody pastes raw ids
# ---------------------------------------------------------------------------

def test_page_offers_asset_and_incident_pickers():
    _enable_governance()
    incident = _assurance_incident()

    page = client.get("/security/governance")
    assert page.status_code == 200
    # Selects, not typed identifiers: the value is the id, the label the name.
    assert 'list="governed-assets"' not in page.text
    assert re.search(r'<option value="MAA-[0-9a-f]{32}">Triage model', page.text)
    assert f'<option value="{incident["id"]}">' in page.text
    assert 'placeholder="MAA-' not in page.text and 'placeholder="MRI-' not in page.text


# ---------------------------------------------------------------------------
# AI literacy (Art. 4)
# ---------------------------------------------------------------------------

def test_literacy_register_through_the_api_and_page():
    _enable_governance()

    _ok(
        client.post(
            f"{_PREFIX}/literacy/requirements",
            json={
                "role": "underwriting_operator",
                "trainings": [
                    {"key": "ai-fundamentals", "title": "AI fundamentals",
                     "validity_days": 365},
                    {"key": "model-limits", "title": "Model limitations",
                     "validity_days": None},
                ],
                "expected_revision": 0,
            },
        )
    )
    requirements = _ok(client.get(f"{_PREFIX}/literacy/requirements"))
    assert requirements["count"] == 1
    assert len(requirements["requirements"][0]["trainings"]) == 2
    assert requirements["data_plane"] == "role_compatibility"
    assert requirements["authoritative_for_compliance"] is False
    assert requirements["reconciliation_required"] is True

    # Duplicate training keys are refused by the request schema itself.
    assert client.post(
        f"{_PREFIX}/literacy/requirements",
        json={
            "role": "underwriting_operator",
            "trainings": [
                {"key": "dup", "title": "One", "validity_days": None},
                {"key": "dup", "title": "Two", "validity_days": None},
            ],
            "expected_revision": 0,
        },
    ).status_code == 422

    _ok(
        client.post(
            f"{_PREFIX}/literacy/assignments",
            json={
                "person": "analyst@example.com",
                "roles": ["underwriting_operator"],
                "expected_revision": 0,
            },
        )
    )
    _ok(
        client.post(
            f"{_PREFIX}/literacy/completions",
            json={
                "person": "analyst@example.com",
                "training": "ai-fundamentals",
                "completed_at": time.time() - 3_600,
                "evidence_ref": "lms:course-17/attempt-1",
            },
        )
    )

    gaps = _ok(client.get(f"{_PREFIX}/literacy/gaps"))
    assert gaps["person_count"] == 1
    assert gaps["counts"] == {"current": 1, "expired": 0, "missing": 1}
    assert gaps["reconciliation_required"] is True

    evidence = _ok(client.get(f"{_PREFIX}/literacy/evidence"))
    exported = json.loads(evidence["evidence"])
    assert exported["regulation"]["article"] == "Art. 4"

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert "analyst@example.com" in page.text
    assert "Model limitations: Not done" in page.text
    assert "Evidence review needed" in page.text


# ---------------------------------------------------------------------------
# Serious incidents (Art. 73) mutations on the assurance router
# ---------------------------------------------------------------------------

def _assurance_incident(occurred_at: float | None = None) -> dict:
    from maverick import model_risk_assurance as mra

    officer = mra.ModelRiskAssuranceOfficer()
    now = time.time()
    observation = officer.observe_asset(
        asset_type="model",
        source="http_acceptance",
        source_id="triage-model",
        display_name="Triage model",
        version_digest=_hex("triage-model-v1"),
        actor="inventory-operator",
        observed_at=now,
        metadata={},
        dependencies=[],
    )
    return officer.record_incident(
        observation["asset_id"],
        source_id="incident-http-1",
        severity="high",
        summary="The triage model misrouted an emergency case.",
        actor="incident-manager",
        occurred_at=now - 7_200 if occurred_at is None else occurred_at,
        evidence_ids=[],
    )


def test_incident_declare_submit_withdraw_through_the_api_and_page():
    _enable_governance()
    incident = _assurance_incident()

    declared = _ok(
        client.post(
            f"{_ASSURANCE}/ai-incidents",
            json={
                "incident_id": incident["id"],
                "category": "critical_infrastructure_disruption",
                "widespread": False,
                "became_aware_at": time.time() - 3_600,
                "causal_link": "reasonably_likely",
                "member_state": "DE",
                "authority": "Bundesnetzagentur market surveillance",
            },
        ),
        expected=201,
    )
    assert declared["status"] == "declared"
    assert declared["declared_by"] == "local:dashboard"

    # A declaration for an unknown assurance incident is a 404, not a write.
    assert client.post(
        f"{_ASSURANCE}/ai-incidents",
        json={
            "incident_id": "MRI-missing",
            "category": "death",
            "became_aware_at": time.time(),
            "member_state": "FR",
            "authority": "DGCCRF",
        },
    ).status_code == 404

    submitted = _ok(
        client.post(
            f"{_ASSURANCE}/ai-incidents/{declared['id']}/submissions",
            json={
                "kind": "initial",
                "submitted_at": time.time(),
                "reference": "authority-portal/2026-0042",
                "expected_revision": declared["revision"],
            },
        )
    )
    assert submitted["status"] == "initial_reported"

    completed = _ok(
        client.post(
            f"{_ASSURANCE}/ai-incidents/{declared['id']}/submissions",
            json={
                "kind": "complete",
                "submitted_at": time.time(),
                "reference": "authority-portal/2026-0042-final",
                "expected_revision": submitted["revision"],
            },
        )
    )
    assert completed["status"] == "complete_reported"

    # A fully reported declaration can no longer be withdrawn: the invalid
    # lifecycle transition is refused as a validation error.
    refused = client.post(
        f"{_ASSURANCE}/ai-incidents/{declared['id']}/withdraw",
        json={
            "rationale": "Review found no serious incident.",
            "expected_revision": completed["revision"],
        },
    )
    assert refused.status_code == 422
    assert "complete_reported -> withdrawn is invalid" in refused.json()["detail"]

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert declared["id"] in page.text
    assert "Declare serious incident" in page.text


def test_incident_withdraw_from_declared_state():
    _enable_governance()
    incident = _assurance_incident()
    declared = _ok(
        client.post(
            f"{_ASSURANCE}/ai-incidents",
            json={
                "incident_id": incident["id"],
                "category": "serious_health_harm",
                "became_aware_at": time.time() - 60,
                "member_state": "IE",
                "authority": "Health Products Regulatory Authority",
            },
        ),
        expected=201,
    )
    withdrawn = _ok(
        client.post(
            f"{_ASSURANCE}/ai-incidents/{declared['id']}/withdraw",
            json={
                "rationale": "Counsel review: not a serious incident.",
                "expected_revision": declared["revision"],
            },
        )
    )
    assert withdrawn["status"] == "withdrawn"

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert "Record filing" not in page.text


# ---------------------------------------------------------------------------
# GRC sync visibility
# ---------------------------------------------------------------------------

def test_grc_sync_status_and_outbound_surface_on_api_and_page():
    _enable_governance()
    from maverick import grc_sync

    _assurance_incident()
    result = grc_sync.run_sync(
        actor="sync-operator",
        writer=lambda _op, _path, _payload: json.dumps(
            {"result": {"sys_id": _FAKE_SYS_ID}}
        ),
    )
    assert result["delivered_count"] == 1

    status = _ok(client.get(f"{_PREFIX}/grc-sync/status"))
    assert status["outbound"]["delivered"] == 1

    outbound = _ok(client.get(f"{_PREFIX}/grc-sync/outbound"))
    assert outbound["count"] == 1
    row = outbound["outbound"][0]
    assert row["kind"] == "incident"
    assert row["remote_id"] == _FAKE_SYS_ID

    assert client.get(
        f"{_PREFIX}/grc-sync/outbound", params={"limit": 0}
    ).status_code == 422

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert _FAKE_SYS_ID in page.text


@pytest.mark.parametrize("global_role", ["viewer", "operator", "auditor"])
def test_grc_dispatch_requires_global_admin_even_for_tenant_admin(monkeypatch, global_role):
    from maverick import grc_sync
    from maverick_dashboard import auth

    _enable_governance()
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:tenant-admin")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: global_role)
    calls = []
    monkeypatch.setattr(grc_sync, "run_sync", lambda **kwargs: calls.append(kwargs))
    response = client.post(f"{_PREFIX}/grc-sync/run", json={"confirm_dispatch": True})
    assert response.status_code == 403
    assert calls == []


@pytest.mark.parametrize("principal", [None, "token:automation", "agent:worker"])
def test_grc_dispatch_requires_an_authenticated_human(monkeypatch, principal):
    from maverick import grc_sync
    from maverick_dashboard import auth

    _enable_governance()
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda value: "admin")
    calls = []
    monkeypatch.setattr(grc_sync, "run_sync", lambda **kwargs: calls.append(kwargs))
    assert client.post(
        f"{_PREFIX}/grc-sync/run", json={"confirm_dispatch": True}
    ).status_code == 403
    assert calls == []


@pytest.mark.parametrize("body", [
    {}, {"confirm_dispatch": False}, {"confirm_dispatch": "true"},
    {"confirm_dispatch": 1}, {"confirm_dispatch": True, "limit": 0},
    {"confirm_dispatch": True, "limit": 201}, {"confirm_dispatch": True, "limit": True},
    {"confirm_dispatch": True, "actor": "user:spoofed"},
    {"confirm_dispatch": True, "writer": "custom"},
])
def test_grc_dispatch_rejects_unconfirmed_unbounded_or_injected_inputs(monkeypatch, body):
    from maverick import grc_sync
    from maverick_dashboard import auth

    _enable_governance()
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "admin")
    calls = []
    monkeypatch.setattr(grc_sync, "run_sync", lambda **kwargs: calls.append(kwargs))
    assert client.post(f"{_PREFIX}/grc-sync/run", json=body).status_code == 422
    assert calls == []


def test_grc_dispatch_records_signed_in_actor_and_avoids_duplicate_delivery(monkeypatch):
    from maverick import audit, grc_sync
    from maverick_dashboard import auth

    _enable_governance()
    _assurance_incident()
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:grc-admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "admin")
    sent = []
    audit_events = []
    monkeypatch.setattr(audit, "record", lambda kind, **fields: audit_events.append(fields) or True)

    def writer(operation, path, payload):
        sent.append((operation, path, payload))
        return json.dumps({"result": {"sys_id": _FAKE_SYS_ID}})

    monkeypatch.setattr(grc_sync, "_default_writer", lambda config: writer)
    body = {"confirm_dispatch": True, "limit": 1}
    first = _ok(client.post(f"{_PREFIX}/grc-sync/run", json=body))
    assert first["delivered_count"] == 1
    assert first["limit"] == 1
    assert len(sent) == 1
    assert first["delivered"][0]["remote_id"] == _FAKE_SYS_ID
    second = _ok(client.post(f"{_PREFIX}/grc-sync/run", json=body))
    assert second["unchanged_count"] == 1
    assert len(sent) == 1
    deliveries = [event for event in audit_events if event["action"] == "deliver_grc_outbound"]
    assert deliveries and all(event["actor"] == "user:grc-admin" for event in deliveries)


def test_grc_dispatch_refuses_disabled_module_before_dispatch(monkeypatch):
    from maverick import grc_sync
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "admin")
    calls = []
    monkeypatch.setattr(grc_sync, "run_sync", lambda **kwargs: calls.append(kwargs))
    assert client.post(
        f"{_PREFIX}/grc-sync/run", json={"confirm_dispatch": True}
    ).status_code == 403
    assert calls == []


@pytest.mark.parametrize("action,body", [
    ("inspect", {"expected_revision": 1}),
    ("resolve", {"expected_revision": 1, "note": "Keep held."}),
])
@pytest.mark.parametrize("role,principal", [("viewer", "user:viewer"), ("operator", "user:operator"),
    ("admin", "token:worker"), ("admin", None)])
def test_grc_reconciliation_requires_named_global_admin(monkeypatch, action, body, role, principal):
    from maverick import grc_sync
    from maverick_dashboard import auth

    _enable_governance()
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda value: role)
    calls = []
    monkeypatch.setattr(grc_sync, f"{action}_delivery", lambda *args, **kwargs: calls.append(kwargs))
    response = client.post(f"{_PREFIX}/grc-sync/outbound/GRO-test/{action}", json=body)
    assert response.status_code == 403
    assert calls == []


@pytest.mark.parametrize("action,body", [
    ("inspect", {"expected_revision": True}),
    ("inspect", {"expected_revision": 1, "remote_id": "../../evil"}),
    ("inspect", {"expected_revision": 1, "reader": "arbitrary"}),
    ("resolve", {"expected_revision": 1, "note": "Review", "actor": "user:spoof"}),
    ("resolve", {"expected_revision": 1, "note": "Review", "evidence_sha256": "fake"}),
    ("resolve", {"expected_revision": 1, "note": ""}),
])
def test_grc_reconciliation_rejects_invalid_or_injected_inputs(monkeypatch, action, body):
    from maverick_dashboard import auth

    _enable_governance()
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda value: "admin")
    assert client.post(f"{_PREFIX}/grc-sync/outbound/GRO-test/{action}", json=body).status_code == 422


def test_grc_reconciliation_journey_records_actor_and_never_resends(monkeypatch):
    from maverick import grc_sync
    from maverick_dashboard import auth

    _enable_governance()
    _assurance_incident()
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:grc-admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda value: "admin")
    sent = []

    def writer(operation, path, payload):
        sent.append(payload)
        return "ERROR: post request failed (Timeout)"

    monkeypatch.setattr(grc_sync, "_default_writer", lambda config: writer)
    _ok(client.post(f"{_PREFIX}/grc-sync/run", json={"confirm_dispatch": True}))
    row = _ok(client.get(f"{_PREFIX}/grc-sync/outbound"))["outbound"][0]
    remote = {**sent[0], "sys_id": _FAKE_SYS_ID}
    reads = []

    def reader(path, params):
        reads.append(path)
        return json.dumps({"result": remote})

    monkeypatch.setattr(grc_sync, "_default_reader", lambda config: reader)
    inspect = _ok(client.post(f"{_PREFIX}/grc-sync/outbound/{row['id']}/inspect",
        json={"expected_revision": row["revision"]}))
    assert inspect["inspection"]["matched"] is True
    resolved = _ok(client.post(f"{_PREFIX}/grc-sync/outbound/{row['id']}/resolve", json={
        "expected_revision": inspect["revision"], "note": "Verified external incident.",
        "evidence_sha256": inspect["inspection"]["evidence_sha256"],
    }))
    assert resolved["status"] == "delivered"
    assert resolved["reconciliation"]["reviewer"] == "user:grc-admin"
    assert len(sent) == 1 and len(reads) == 2
    page = client.get("/security/governance")
    assert 'id="gov-grc-recovery"' in page.text
    assert client.get("/static/lightwork-grc-recovery.js").status_code == 200


# ---------------------------------------------------------------------------
# Art. 26 deployer obligations
# ---------------------------------------------------------------------------

def test_deployer_register_through_the_api():
    _enable_governance()
    asset_id = "MAA-" + _hex("deployed-model")[:32]

    opened = _ok(
        client.post(
            f"{_PREFIX}/deployer",
            json={"asset_id": asset_id, "workplace_use": True},
        ),
        expected=201,
    )
    # 5 always-applicable + oversight + the flagged workplace duty.
    assert opened["status"]["total"] == 7
    assert opened["status"]["oversight_persons"] == []
    record_id = opened["record"]["id"]

    # Oversight cannot be asserted like an ordinary obligation.
    refused = client.post(
        f"{_PREFIX}/deployer/{record_id}/obligations",
        json={
            "obligation": "human_oversight_assignment",
            "reference": "doc://oversight",
            "expected_revision": opened["record"]["revision"],
        },
    )
    assert refused.status_code == 409
    assert "26(2)" in refused.json()["detail"]

    state = _ok(
        client.post(
            f"{_PREFIX}/deployer/{record_id}/oversight",
            json={
                "persons": ["Ada Lovelace", "Grace Hopper"],
                "reference": "doc://oversight-competence",
                "expected_revision": opened["record"]["revision"],
            },
        )
    )
    assert state["oversight_persons"] == ["Ada Lovelace", "Grace Hopper"]

    asserted = _ok(
        client.post(
            f"{_PREFIX}/deployer/{record_id}/obligations",
            json={
                "obligation": "log_retention",
                "reference": "runbook://log-retention-183d",
                "expected_revision": state["revision"],
            },
        )
    )
    assert asserted["asserted"] == 2

    listing = _ok(client.get(f"{_PREFIX}/deployer"))
    assert listing["count"] == 1
    assert "use_per_instructions" in listing["obligations"]
    assert "worker_information" in listing["conditional_obligations"]
    fetched = _ok(client.get(f"{_PREFIX}/deployer/{record_id}"))
    assert fetched["status"]["flags"]["workplace_use"] is True
    assert client.get(f"{_PREFIX}/deployer/ECY-{'0' * 24}").status_code == 404


def test_workspace_page_renders_the_gpai_and_deployer_panels():
    _enable_governance()
    asset_id = "MAA-" + _hex("panel-model")[:32]
    _ok(client.post(f"{_PREFIX}/gpai",
                    json={"asset_id": asset_id, "systemic_risk": True}),
        expected=201)
    _ok(client.post(f"{_PREFIX}/deployer",
                    json={"asset_id": asset_id, "workplace_use": True}),
        expected=201)

    page = client.get("/security/governance")
    assert page.status_code == 200
    assert "General-purpose AI models you provide" in page.text
    assert "High-risk AI systems you use" in page.text
    assert "Nobody named yet" in page.text          # oversight not yet named
    assert 'id="gpai-assert"' in page.text
    assert 'id="deployer-oversight"' in page.text
    assert asset_id in page.text
