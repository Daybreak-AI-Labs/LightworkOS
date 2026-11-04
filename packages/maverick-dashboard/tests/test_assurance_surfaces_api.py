"""HTTP acceptance for the assurance surfaces.

Covers the portfolio trend/drill-through, the AI vendor-risk lifecycle, the
drift-monitoring lifecycle, the agent/MCP topology wiring and incident clocks,
including permission boundaries, tenant boundaries, and safe-projection
checks.
"""
from __future__ import annotations

import hashlib
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

[drift_monitoring]
enable = true
bins = 5
min_samples = 10
psi_threshold = 0.15
kl_threshold = 0.08
embedding_cosine_threshold = 0.1
performance_decay_threshold = 0.05
evidence_validity_seconds = 3600
"""


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import audit, config
    from maverick.audit import writer as audit_writer

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


def _governed_asset():
    """One observed, declared, and independently reviewed model asset."""
    from maverick import model_risk_assurance as mra

    officer = mra.ModelRiskAssuranceOfficer()
    now = time.time()
    observation = officer.observe_asset(
        asset_type="model",
        source="http_acceptance",
        source_id="credit-model",
        display_name="Credit model",
        version_digest=_hex("credit-model-v1"),
        actor="inventory-operator",
        observed_at=now,
        metadata={"environment": "test"},
        dependencies=[],
    )
    proposed = officer.declare_asset(
        observation["asset_id"],
        owner="model-owner",
        purpose="Human-reviewed credit decision support.",
        intended_use="Rank applications for trained underwriters.",
        risk_tier="high",
        risk_context={
            "human_oversight": True,
            "high_risk_domains": ["essential_services"],
        },
        eu_ai_act={
            "category": "high_risk",
            "asserted_by": "qualified-reviewer",
            "asserted_at": now,
            "as_of": "2026-08-23",
            "source_ref": mra.EU_AI_ACT_METADATA["source"],
            "rationale": "Reviewed credit-access deployment context.",
        },
        actor="model-owner",
    )
    officer.review_declaration(
        observation["asset_id"],
        decision="approved",
        rationale="Ownership, use, and monitoring obligations reviewed.",
        reviewer="independent-risk-reviewer",
        expected_revision=proposed["revision"],
    )
    return observation


# Portfolio trend and contributor drill-through -------------------------------


def test_portfolio_trend_routes_gate_wire_and_bound(monkeypatch):
    base = "/api/v1/security/assurance/portfolio-risk"
    assert client.get(f"{base}/trend").status_code == 403

    _reset_config_with("\n[portfolio_risk]\nenable = true\n")
    _governed_asset()
    snapshot = _ok(client.post(
        f"{base}/snapshots", json={"expected_revision": 0}
    ))
    period = snapshot["period_id"]

    trend = _ok(client.get(f"{base}/trend"))
    assert trend["current_period_id"] == period
    assert trend["comparison_available"] is False
    assert trend["legal_certification"] is False
    assert len(trend["trend_sha256"]) == 64

    contributor_id = snapshot["report"]["contributors"][0]["contributor_id"]
    row = _ok(client.get(f"{base}/snapshots/{period}/contributors/{contributor_id}"))
    assert row["contributor_id"] == contributor_id
    assert row["period_id"] == period
    # Identity projection only — never summaries, citations, or acceptances.
    assert "summary" not in row
    assert "source_citations" not in row
    assert "acceptance" not in row

    assert client.get(
        f"{base}/snapshots/{period}/contributors/absent-id"
    ).status_code == 404
    assert client.get(
        f"{base}/snapshots/{period}/contributors/..%2Fescape"
    ).status_code in (404, 422)
    assert client.get(f"{base}/trend?contributor_limit=0").status_code == 422
    assert client.get(f"{base}/trend?contributor_limit=501").status_code == 422

    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "has_permission", lambda *_args: False)
    assert client.get(f"{base}/trend").status_code == 403


# AI vendor risk --------------------------------------------------------------


def test_tenant_scoped_routes_refuse_without_an_active_tenant():
    base = "/api/v1/security/assurance/ai-vendor"
    assert client.get(f"{base}/assessments").status_code == 409
    assert client.get(
        "/api/v1/security/assurance/drift/evaluations"
    ).status_code == 409
    assert client.post(
        f"{base}/assessments",
        json={"vendor": "Acme AI", "answers": {}, "documents": [], "use_prior": False},
    ).status_code == 409


def test_ai_vendor_lifecycle_over_http_is_safe_and_reviewable(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    _reset_config_with("\n[ai_vendor_risk]\nenable = true\n")
    base = "/api/v1/security/assurance/ai-vendor"

    created = _ok(client.post(
        f"{base}/assessments",
        json={
            "vendor": "Acme AI",
            "answers": {"aiv_provenance": "no", "aiv_incidents": "yes"},
            "documents": [],
            "use_prior": False,
        },
    ), 201)
    assert created["status"] == "pending_review"
    assert created["result"]["risk_rating"] == "high"
    assert created["document_count"] == 0
    assert created["legal_certification"] is False
    # The safe projection never exposes documents, locators, or excerpts.
    assert "documents" not in created
    assert "answer_sources" not in created
    for answer in created["answers"].values():
        assert set(answer) == {
            "answer", "note", "source", "confidence", "review_required",
        }

    listing = _ok(client.get(f"{base}/assessments"))
    assert listing["count"] == 1
    record_id = created["id"]
    detail = _ok(client.get(f"{base}/assessments/{record_id}"))
    assert detail["id"] == record_id
    assert client.get(f"{base}/assessments/AVR-missing").status_code == 404

    reviewed = _ok(client.post(
        f"{base}/assessments/{record_id}/review",
        json={
            "decision": "approved",
            "rationale": "Reviewed against the diligence rubric.",
            "expected_revision": created["revision"],
        },
    ))
    assert reviewed["review"]["decision"] == "approved"

    plan = _ok(client.get(f"{base}/prior-answer-plan?vendor_name=Acme AI"))
    assert plan["review_required"] is True
    assert set(plan["skipped_question_ids"]) >= {"aiv_provenance", "aiv_incidents"}

    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "has_global_permission", lambda *_args: False)
    assert client.post(
        f"{base}/assessments/{record_id}/review",
        json={
            "decision": "approved",
            "rationale": "Only a global admin may hold review authority.",
            "expected_revision": 2,
        },
    ).status_code == 403


# Drift monitoring ------------------------------------------------------------


def test_drift_lifecycle_over_http_stays_aggregate_only(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    observation = _governed_asset()
    base = "/api/v1/security/assurance/drift"
    stable = {"score": ([0.0] * 50) + ([1.0] * 50)}

    baseline = _ok(client.post(
        f"{base}/baselines",
        json={
            "asset_id": observation["asset_id"],
            "source_id": "production-window",
            "feature_samples": stable,
        },
    ), 201)
    assert baseline["asset_id"] == observation["asset_id"]
    assert baseline["monitored"]["feature_names"] == ["score"]
    assert baseline["legal_certification"] is False
    # Aggregate-only projection: raw samples never leave the service.
    assert "feature_samples" not in baseline
    assert "features" not in baseline

    listed = _ok(client.get(f"{base}/baselines"))
    assert [row["id"] for row in listed["items"]] == [baseline["id"]]
    assert "features" not in listed["items"][0]
    assert listed["items"][0]["monitored"]["feature_names"] == ["score"]

    fetched = _ok(client.get(f"{base}/baselines/{baseline['id']}"))
    assert fetched["id"] == baseline["id"]
    assert client.get(f"{base}/baselines/MDB-missing").status_code == 404

    report = _ok(client.post(
        f"{base}/baselines/{baseline['id']}/evaluations",
        json={
            "run_id": "shifted-run",
            "feature_samples": {"score": [10.0] * 100},
        },
    ), 201)
    assert report["result"] == "failed"
    assert report["alert"] is not None
    assert report["evidence_id"]
    assert "feature_samples" not in report

    listing = _ok(client.get(
        f"{base}/evaluations?asset_id={observation['asset_id']}"
    ))
    assert listing["count"] >= 1
    kinds = {row.get("result") for row in listing["items"]}
    assert "failed" in kinds
    for row in listing["items"]:
        assert "feature_samples" not in row


def test_drift_routes_refuse_when_disabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    from maverick import config

    Path(config.config_path()).write_text(
        _BASE_CONFIG.split("[drift_monitoring]")[0], encoding="utf-8"
    )
    config.reset_config_cache()
    response = client.get(
        "/api/v1/security/assurance/drift/baselines/MDB-anything"
    )
    assert response.status_code == 403
    assert "drift monitoring is disabled" in response.json()["detail"]
    # The evaluations listing reads already-safe MRA evidence, so it stays
    # readable while the capture/evaluate surface is off.
    assert client.get(
        "/api/v1/security/assurance/drift/evaluations"
    ).status_code == 200


# Agent and MCP topology ------------------------------------------------------


def test_agent_topology_routes_wire_permissions_and_error_mapping(monkeypatch):
    from maverick import agent_topology as topo

    calls: dict = {}
    monkeypatch.setattr(topo, "enabled", lambda: True)
    monkeypatch.setattr(
        topo, "agent_view", lambda name: {"agent": name, "reachable": []}
    )
    monkeypatch.setattr(
        topo,
        "blast_radius",
        lambda kind, name: {"kind": kind, "name": name, "reached_by": []},
    )

    def sync(*, actor):
        calls["actor"] = actor
        return {"synced": 0}

    monkeypatch.setattr(topo, "sync_mcp_inventory", sync)

    base = "/api/v1/security/assurance/agent-topology"
    monkeypatch.setattr(topo, "agent_names", lambda: ["planner", "reviewer"])
    assert _ok(client.get(f"{base}/agents")) == {"items": ["planner", "reviewer"], "count": 2}
    view = _ok(client.get(f"{base}/agents/planner"))
    assert view["agent"] == "planner"
    radius = _ok(client.get(f"{base}/blast-radius/tool/web_fetch"))
    assert radius == {"kind": "tool", "name": "web_fetch", "reached_by": []}
    _ok(client.post(f"{base}/mcp/sync"))
    assert calls["actor"] == "local:dashboard"

    def missing(name):
        raise KeyError(name)

    monkeypatch.setattr(topo, "agent_view", missing)
    assert client.get(f"{base}/agents/absent").status_code == 404

    def invalid(kind, name):
        raise ValueError("unknown topology kind")

    monkeypatch.setattr(topo, "blast_radius", invalid)
    assert client.get(f"{base}/blast-radius/nope/x").status_code == 422

    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "has_global_permission", lambda *_args: False)
    assert client.post(f"{base}/mcp/sync").status_code == 403


# Page panels -----------------------------------------------------------------


def test_assurance_page_renders_new_panels_and_gates_admin_actions(monkeypatch):
    page = client.get("/security/assurance")
    assert page.status_code == 200
    text = page.text
    assert "Suppliers, drift and agent reach" in text
    assert 'id="drift-baseline-create"' in text
    assert 'id="ai-vendor-create"' in text

    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "has_global_permission", lambda *_args: False)
    gated = client.get("/security/assurance").text
    assert 'id="agent-topology-sync"' not in gated


def test_red_team_schedule_dispatch_materializes_a_real_campaign(
    tmp_path, monkeypatch,
):
    """Red-team schedule -> run-due -> live campaign, then cancel."""
    from maverick import agent_trust
    from maverick import model_risk_assurance as mra

    _reset_config_with(
        "\n[external_agents]\n"
        "enable = true\n"
        "\n[red_team_assurance]\n"
        "enable = true\n"
        'commitment_secret_ref = "MAVERICK_RED_TEAM_COMMITMENT_KEY"\n'  # pragma: allowlist secret
        "max_cases = 12\n"
        "max_response_bytes = 65536\n"
        "campaign_ttl_seconds = 86400\n"
        "evidence_validity_seconds = 604800\n"
    )
    monkeypatch.setenv(
        "MAVERICK_RED_TEAM_COMMITMENT_KEY",
        "test-only-red-team-commitment-key-32-bytes-minimum",
    )
    jwks = tmp_path / "runner-jwks.json"
    jwks.write_text('{"keys":[{"kty":"OKP","kid":"one"}]}', encoding="utf-8")
    trusted = agent_trust.TrustedAgent(
        id="external-one",
        direction="inbound",
        jwt_issuer="https://issuer.example",
        jwt_audience="lightwork",
        jwks_file=str(jwks),
    )
    monkeypatch.setattr(agent_trust, "lookup", lambda _agent_id: trusted)

    officer = mra.ModelRiskAssuranceOfficer()
    observation = officer.observe_asset(
        asset_type="agent",
        source="http_acceptance",
        source_id="scheduled-target",
        display_name="Scheduled target",
        version_digest=_hex("scheduled-target-v1"),
        actor="inventory-operator",
        observed_at=time.time(),
        metadata={"environment": "test"},
        dependencies=[],
    )

    created = _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules",
        json={
            "asset_id": observation["asset_id"],
            "external_agent_id": "external-one",
            "idempotency_key": "http-schedule-one",
            "safe_target_environment": True,
            "cadence_seconds": 3600,
        },
    ), 201)
    assert created["status"] == "active"
    assert created["run_count"] == 0
    # The safe projection never exposes commitments, leases, or raw payloads.
    assert "case_leases" not in created
    assert "result_commitments" not in created

    dispatched = _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules/run-due",
        json={"limit": 5},
    ))
    assert dispatched["count"] == 1
    assert dispatched["failures"] == []
    campaign_id = dispatched["campaigns"][0]["id"]

    campaigns = _ok(client.get(
        "/api/v1/security/assurance/red-team/campaigns"
    ))["campaigns"]
    assert any(row["id"] == campaign_id for row in campaigns)

    schedule = _ok(client.get(
        f"/api/v1/security/assurance/red-team/schedules/{created['id']}"
    ))
    assert schedule["run_count"] == 1
    assert schedule["last_campaign_id"] == campaign_id
    assert schedule["next_run_at"] > created["next_run_at"]

    cancelled = _ok(client.post(
        f"/api/v1/security/assurance/red-team/schedules/{created['id']}/cancel",
        json={
            "expected_revision": schedule["revision"],
            "rationale": "Acceptance pass complete.",
        },
    ))
    assert cancelled["status"] == "cancelled"
    assert _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules/run-due",
        json={},
    ))["count"] == 0


def test_ai_incident_clocks_surface_on_api_and_page():
    """Declared Art. 73 incident clocks are visible, drafts gated."""
    import time as _time

    from maverick import ai_incident_reporting as air
    from maverick import model_risk_assurance as mra

    # Disabled: the routes fail closed and the page explains the knob.
    assert client.get(
        "/api/v1/security/assurance/ai-incidents"
    ).status_code == 403
    page = client.get("/security/assurance")
    assert page.status_code == 200
    assert "Serious-incident reporting is turned off" in page.text

    _reset_config_with("\n[ai_incident_reporting]\nenable = true\n")

    officer = mra.ModelRiskAssuranceOfficer()
    now = _time.time()
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
    incident = officer.record_incident(
        observation["asset_id"],
        source_id="incident-http-1",
        severity="high",
        summary="The triage model misrouted an emergency case.",
        actor="incident-manager",
        occurred_at=now - 7_200,
        evidence_ids=[],
    )
    declared = air.declare_serious_incident(
        incident["id"],
        category="critical_infrastructure_disruption",
        widespread=False,
        became_aware_at=now - 3_600,
        causal_link="reasonably_likely",
        member_state="DE",
        authority="Bundesnetzagentur market surveillance",
        declared_by="incident-manager",
    )

    listing = _ok(client.get("/api/v1/security/assurance/ai-incidents"))
    assert listing["count"] == 1
    row = listing["declarations"][0]
    assert row["id"] == declared["id"]
    assert row["clock"]["overdue"] is False
    assert row["deadline_citation"] == "Art. 73(3)"

    categories = _ok(client.get(
        "/api/v1/security/assurance/ai-incidents/categories"
    ))
    assert categories["categories"]["death"]["window_days"] == 10
    assert categories["regulation"]["consolidated"] == "2026-07-27"

    assert _ok(client.get(
        "/api/v1/security/assurance/ai-incidents/overdue"
    ))["count"] == 0

    draft = _ok(client.get(
        f"/api/v1/security/assurance/ai-incidents/{declared['id']}/report"
    ))
    assert "Art. 73(3)" in draft["draft"]
    assert client.get(
        "/api/v1/security/assurance/ai-incidents/ASI-missing/report"
    ).status_code == 404

    page = client.get("/security/assurance")
    assert page.status_code == 200
    assert "Serious-incident deadlines" in page.text
    assert declared["id"] in page.text
    assert " days left" in page.text
