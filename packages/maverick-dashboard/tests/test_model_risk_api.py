"""HTTP contract for the governed Model Risk assurance surface."""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

from test_support.starlette_state import patch_state

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_model_risk(tmp_path, monkeypatch):
    from maverick import audit, config
    from maverick.audit import writer as audit_writer

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """[evidence_graph]
enable = true

[model_risk_assurance]
enable = true
gate_promotions = true
""",
        encoding="utf-8",
    )
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


def _enable_portfolio() -> None:
    from maverick import config

    path = Path(config.config_path())
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n[portfolio_risk]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()


def test_red_team_admin_campaign_lifecycle_is_actor_bound(monkeypatch):
    from maverick import red_team_assurance as rta

    calls: dict = {}
    monkeypatch.setattr(rta, "enabled", lambda: True)
    monkeypatch.setattr(
        rta,
        "starter_suite_manifest",
        lambda: {"suite_id": "lightwork-admission-starter"},
    )
    monkeypatch.setattr(
        rta,
        "list_campaigns",
        lambda **_kwargs: {
            "items": [{"id": "RTC-one", "status": "running"}],
            "count": 1,
            "truncated": False,
            "limit": 100,
        },
    )
    monkeypatch.setattr(
        rta,
        "get_campaign",
        lambda campaign_id: {"id": campaign_id, "status": "running"},
    )

    def create(**kwargs):
        calls["create"] = kwargs
        return {"id": "RTC-one", "status": "running", "revision": 1}

    def finalize(campaign_id, **kwargs):
        calls["finalize"] = (campaign_id, kwargs)
        return {"id": campaign_id, "status": "completed", "revision": 2}

    def cancel(campaign_id, **kwargs):
        calls["cancel"] = (campaign_id, kwargs)
        return {"id": campaign_id, "status": "cancelled", "revision": 2}

    monkeypatch.setattr(rta, "create_campaign", create)
    monkeypatch.setattr(rta, "finalize_campaign", finalize)
    monkeypatch.setattr(rta, "cancel_campaign", cancel)

    body = {
        "asset_id": "MAA-" + ("a" * 32),
        "external_agent_id": "external-one",
        "idempotency_key": "campaign-one",
        "safe_target_environment": True,
        "case_keys": ["prompt-injection-01"],
        "ttl_seconds": 3600,
    }
    created = _ok(client.post(
        "/api/v1/security/assurance/red-team/campaigns",
        json=body,
    ), 201)
    assert created["status"] == "running"
    assert calls["create"]["actor"] == "local:dashboard"
    assert _ok(client.get(
        "/api/v1/security/assurance/red-team/campaigns"
    ))["campaigns"][0]["id"] == "RTC-one"
    assert _ok(client.get(
        "/api/v1/security/assurance/red-team/suite"
    ))["suite_id"] == "lightwork-admission-starter"

    finalized = _ok(client.post(
        "/api/v1/security/assurance/red-team/campaigns/RTC-one/finalize",
        json={"force_incomplete": False},
    ))
    assert finalized["status"] == "completed"
    assert calls["finalize"] == (
        "RTC-one",
        {"actor": "local:dashboard", "force_incomplete": False},
    )

    cancelled = _ok(client.post(
        "/api/v1/security/assurance/red-team/campaigns/RTC-two/cancel",
        json={"expected_revision": 1, "rationale": "Human stop."},
    ))
    assert cancelled["status"] == "cancelled"
    assert calls["cancel"][1]["actor"] == "local:dashboard"


def test_red_team_schedule_and_dispatch_http_lifecycle(monkeypatch):
    from maverick import red_team_assurance as rta

    calls: dict[str, dict] = {}
    monkeypatch.setattr(rta, "enabled", lambda: True)
    monkeypatch.setattr(
        rta,
        "list_schedules",
        lambda **kwargs: {
            "items": [{"id": "RTS-one", "status": "active"}],
            "limit": kwargs["limit"],
        },
    )
    monkeypatch.setattr(
        rta,
        "get_schedule",
        lambda schedule_id: {"id": schedule_id, "status": "active", "revision": 1},
    )

    def create(**kwargs):
        calls["create"] = kwargs
        return {"id": "RTS-one", "status": "active", "revision": 1}

    def run_due(**kwargs):
        calls["run_due"] = kwargs
        return {"count": 1, "campaigns": [{"id": "RTC-one"}], "failures": []}

    def materialize(schedule_id, **kwargs):
        calls["materialize"] = {"schedule_id": schedule_id, **kwargs}
        return {"id": "RTC-one", "status": "running"}

    def cancel(schedule_id, **kwargs):
        calls["cancel"] = {"schedule_id": schedule_id, **kwargs}
        return {"id": schedule_id, "status": "cancelled", "revision": 2}

    monkeypatch.setattr(rta, "create_schedule", create)
    monkeypatch.setattr(rta, "run_due_schedules", run_due)
    monkeypatch.setattr(rta, "materialize_due_schedule", materialize)
    monkeypatch.setattr(rta, "cancel_schedule", cancel)

    assert _ok(client.get(
        "/api/v1/security/assurance/red-team/schedules?limit=10"
    ))["limit"] == 10
    assert _ok(client.get(
        "/api/v1/security/assurance/red-team/schedules/RTS-one"
    ))["id"] == "RTS-one"
    created = _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules",
        json={
            "asset_id": "MAA-" + ("a" * 32),
            "external_agent_id": "external-one",
            "idempotency_key": "weekly-red-team",
            "safe_target_environment": True,
            "cadence_seconds": 604800,
            "case_keys": ["prompt-injection-01"],
            "campaign_ttl_seconds": 3600,
        },
    ), expected=201)
    assert created["id"] == "RTS-one"
    assert calls["create"]["actor"] == "local:dashboard"

    due = _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules/run-due",
        json={"limit": 5},
    ))
    assert due["count"] == 1
    assert calls["run_due"] == {"actor": "local:dashboard", "limit": 5}
    campaign = _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules/RTS-one/materialize"
    ))
    assert campaign["id"] == "RTC-one"
    stopped = _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules/RTS-one/cancel",
        json={"expected_revision": 1, "rationale": "Campaign retired."},
    ))
    assert stopped["status"] == "cancelled"
    assert calls["materialize"]["actor"] == "local:dashboard"
    assert calls["cancel"]["actor"] == "local:dashboard"


def test_portfolio_risk_report_and_snapshot_api(monkeypatch):
    from maverick import portfolio_risk

    calls: dict = {}
    monkeypatch.setattr(portfolio_risk, "enabled", lambda: True)
    monkeypatch.setattr(
        portfolio_risk,
        "current_report",
        lambda: {"portfolio_score": 75, "formula_version": "v1"},
    )
    monkeypatch.setattr(
        portfolio_risk,
        "list_snapshots",
        lambda: [{"id": "MRP-one", "period_id": "2026-Q3"}],
    )
    monkeypatch.setattr(
        portfolio_risk,
        "get_snapshot",
        lambda period_id: {"id": "MRP-one", "period_id": period_id},
    )
    monkeypatch.setattr(
        portfolio_risk,
        "portfolio_trend",
        lambda **kwargs: {
            "schema": portfolio_risk.TREND_SCHEMA,
            "current_period_id": "2026-Q3",
            "contributor_limit": kwargs["contributor_limit"],
        },
    )
    monkeypatch.setattr(
        portfolio_risk,
        "get_contributor_drillthrough",
        lambda period_id, contributor_id: {
            "period_id": period_id,
            "contributor_id": contributor_id,
            "finding_id": "MRF-one",
        },
    )

    def refresh(**kwargs):
        calls.update(kwargs)
        return {"id": "MRP-one", "period_id": kwargs["period_id"], "revision": 1}

    monkeypatch.setattr(portfolio_risk, "refresh_current_snapshot", refresh)

    report = _ok(client.get(
        "/api/v1/security/assurance/portfolio-risk/report"
    ))
    assert report["portfolio_score"] == 75
    snapshots = _ok(client.get(
        "/api/v1/security/assurance/portfolio-risk/snapshots"
    ))
    assert snapshots["snapshots"][0]["period_id"] == "2026-Q3"
    snapshot = _ok(client.get(
        "/api/v1/security/assurance/portfolio-risk/snapshots/2026-Q3"
    ))
    assert snapshot["period_id"] == "2026-Q3"
    trend = _ok(client.get(
        "/api/v1/security/assurance/portfolio-risk/trend?contributor_limit=25"
    ))
    assert trend["current_period_id"] == "2026-Q3"
    assert trend["contributor_limit"] == 25
    contributor = _ok(client.get(
        "/api/v1/security/assurance/portfolio-risk/snapshots/2026-Q3/"
        "contributors/contributor-one"
    ))
    assert contributor == {
        "period_id": "2026-Q3",
        "contributor_id": "contributor-one",
        "finding_id": "MRF-one",
    }
    refreshed = _ok(client.post(
        "/api/v1/security/assurance/portfolio-risk/snapshots",
        json={"expected_revision": 0, "period_id": "2026-Q3"},
    ))
    assert refreshed["revision"] == 1
    assert calls == {
        "actor": "local:dashboard",
        "expected_revision": 0,
        "period_id": "2026-Q3",
    }


def test_ai_regulatory_bridge_http_lifecycle_is_authority_bound(monkeypatch):
    from maverick import ai_regulatory_feed as arf

    calls: dict[str, dict] = {}
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(arf, "enabled", lambda: True)
    monkeypatch.setattr(
        arf,
        "list_notices",
        lambda **kwargs: [{"id": "ARN-one", "limit": kwargs["limit"]}],
    )
    monkeypatch.setattr(
        arf,
        "get_notice",
        lambda notice_id: {"id": notice_id, "delivery": {"status": "pending"}},
    )
    monkeypatch.setattr(
        arf,
        "list_active_staleness",
        lambda **kwargs: [{"id": "ARS-one", **kwargs}],
    )

    def sync(alert_id, **kwargs):
        calls["sync"] = {"alert_id": alert_id, **kwargs}
        return {"notice": {"id": "ARN-one"}, "staleness": {"id": "ARS-one"}}

    def deliver(notice_id, **kwargs):
        calls["deliver"] = {"notice_id": notice_id, **kwargs}
        return {"id": notice_id, "delivery": {"status": "sent"}}

    def resolve(staleness_id, **kwargs):
        calls["resolve"] = {"staleness_id": staleness_id, **kwargs}
        return {"id": staleness_id, "state": "resolved"}

    monkeypatch.setattr(arf, "sync_finance_alert", sync)
    monkeypatch.setattr(arf, "deliver_notice", deliver)
    monkeypatch.setattr(arf, "resolve_staleness", resolve)

    notices = _ok(client.get(
        "/api/v1/security/assurance/ai-regulatory-feed/notices?limit=25"
    ))
    assert notices["notices"] == [{"id": "ARN-one", "limit": 25}]
    notice = _ok(client.get(
        "/api/v1/security/assurance/ai-regulatory-feed/notices/ARN-one"
    ))
    assert notice["id"] == "ARN-one"
    stale = _ok(client.get(
        "/api/v1/security/assurance/ai-regulatory-feed/staleness"
        "?evidence_id=MRE-one&limit=10"
    ))
    assert stale["staleness"][0]["evidence_id"] == "MRE-one"

    synced = _ok(client.post(
        "/api/v1/security/assurance/ai-regulatory-feed/alerts/alert-one/sync",
        json={
            "deliver": True,
            "rules": [
                {
                    "rule_id": "eu-ai-act",
                    "regimes": ["eu-ai-act"],
                    "policy_ids": ["default"],
                    "control_ids": ["CTRL-AI"],
                }
            ],
        },
    ), expected=201)
    assert synced["notice"]["id"] == "ARN-one"
    assert calls["sync"] == {
        "alert_id": "alert-one",
        "rules": [
            {
                "rule_id": "eu-ai-act",
                "regimes": ["eu-ai-act"],
                "domains": [],
                "policy_ids": ["default"],
                "control_ids": ["CTRL-AI"],
                "asset_ids": [],
                "evidence_kinds": [],
                "evidence_ids": [],
            }
        ],
        "actor": "local:dashboard",
        "deliver": True,
    }

    sent = _ok(client.post(
        "/api/v1/security/assurance/ai-regulatory-feed/notices/ARN-one/deliver",
        json={"expected_revision": 1},
    ))
    assert sent["delivery"]["status"] == "sent"
    resolved = _ok(client.post(
        "/api/v1/security/assurance/ai-regulatory-feed/staleness/ARS-one/resolve",
        json={"expected_revision": 1, "resolution": "Evidence refreshed."},
    ))
    assert resolved["state"] == "resolved"
    assert calls["deliver"]["actor"] == "local:dashboard"
    assert calls["resolve"]["actor"] == "local:dashboard"


def test_ai_vendor_risk_http_lifecycle_is_safe_and_review_gated(monkeypatch):
    from maverick import ai_vendor_risk as avr

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(avr, "enabled", lambda: True)
    calls: dict[str, dict] = {}
    record = {
        "id": "AIV-one",
        "vendor": "Acme AI",
        "status": "draft",
        "revision": 1,
        "created_at": 1.0,
        "assessment_sha256": "a" * 64,
        "template_digest": "b" * 64,
        "answers": {
            "aiv_provenance": {"answer": "yes", "note": "Reviewed note."},
        },
        "answer_sources": {
            "aiv_provenance": {
                "kind": "document",
                "confidence": 0.8,
                "review_required": True,
                "quote": "secret source excerpt",
            }
        },
        "result": {
            "risk_rating": "medium",
            "residual_risk": 25,
            "answered": 1,
            "total": 8,
            "findings": [],
        },
        "documents": [{"raw_locator": "must-not-leak"}],
        "skipped_prior_questions": [],
        "review": None,
    }
    monkeypatch.setattr(
        avr,
        "list_vendor_assessments",
        lambda **kwargs: {"items": [{"id": "AIV-one"}], "limit": kwargs["limit"]},
    )
    monkeypatch.setattr(avr, "get_vendor_assessment", lambda _record_id: record)
    monkeypatch.setattr(
        avr,
        "prior_answer_plan",
        lambda _vendor: {
            "vendor_key": "acme-ai",
            "prior_record_id": "AIV-old",
            "skipped": {"aiv_provenance": {}},
            "ask": ["aiv_incidents"],
        },
    )

    def draft(vendor, **kwargs):
        calls["draft"] = {"vendor": vendor, **kwargs}
        return record

    def review(record_id, **kwargs):
        calls["review"] = {"record_id": record_id, **kwargs}
        return {**record, "status": "approved", "revision": 2}

    def project(record_id, asset_id, **kwargs):
        calls["project"] = {
            "record_id": record_id,
            "asset_id": asset_id,
            **kwargs,
        }
        return {"id": "MRE-vendor", "evidence_kind": "vendor_assessment"}

    monkeypatch.setattr(avr, "draft_vendor_assessment", draft)
    monkeypatch.setattr(avr, "review_vendor_assessment", review)
    monkeypatch.setattr(avr, "project_to_model_risk", project)

    listed = _ok(client.get(
        "/api/v1/security/assurance/ai-vendor/assessments?limit=25"
    ))
    assert listed["limit"] == 25
    detail = _ok(client.get(
        "/api/v1/security/assurance/ai-vendor/assessments/AIV-one"
    ))
    assert detail["document_count"] == 1
    assert detail["answers"]["aiv_provenance"]["source"] == "document"
    assert "must-not-leak" not in str(detail)
    assert "secret source excerpt" not in str(detail)
    plan = _ok(client.get(
        "/api/v1/security/assurance/ai-vendor/prior-answer-plan"
        "?vendor_name=Acme%20AI"
    ))
    assert plan["skipped_question_ids"] == ["aiv_provenance"]

    drafted = _ok(client.post(
        "/api/v1/security/assurance/ai-vendor/assessments",
        json={
            "vendor": "Acme AI",
            "answers": {"aiv_provenance": "yes"},
            "documents": [],
            "use_prior": True,
        },
    ), expected=201)
    assert drafted["status"] == "draft"
    assert calls["draft"]["actor"] == "local:dashboard"
    assert calls["draft"]["document_results"] == []

    reviewed = _ok(client.post(
        "/api/v1/security/assurance/ai-vendor/assessments/AIV-one/review",
        json={
            "decision": "approved",
            "rationale": "Evidence reviewed independently.",
            "expected_revision": 1,
        },
    ))
    assert reviewed["status"] == "approved"
    assert calls["review"]["reviewer"] == "local:dashboard"

    asset_id = "MAA-" + ("a" * 32)
    projected = _ok(client.post(
        "/api/v1/security/assurance/ai-vendor/assessments/AIV-one/project",
        json={"asset_id": asset_id, "valid_until": time.time() + 3600},
    ))
    assert projected["id"] == "MRE-vendor"
    assert calls["project"]["actor"] == "local:dashboard"


def test_real_hierarchy_http_flow_rejects_cycles_and_supports_detach():
    now = time.time()
    source = "hierarchy-api"

    def observe(label, asset_type):
        return _ok(client.post(
            "/api/v1/security/assurance/model-risk/observations",
            json={
                "asset_type": asset_type,
                "source": source,
                "source_id": label,
                "display_name": label,
                "version_digest": hashlib.sha256(label.encode()).hexdigest(),
                "metadata": {},
                "dependencies": [],
            },
        ))

    system = observe("system-one", "system")
    component_a = observe("component-a", "component")
    component_b = observe("component-b", "component")

    def declare(row, parent=None):
        body = {
            "asset_id": row["asset_id"],
            "owner": "AI Risk Committee",
            "purpose": "Governed hierarchy API test.",
            "intended_use": "Decision support with human review.",
            "risk_tier": "medium",
            "risk_context": {"human_oversight": True},
            "eu_ai_act": {
                "category": "not_applicable",
                "asserted_at": now,
                "as_of": "2026-07-21",
                "source_ref": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
                "rationale": "Qualified human test assertion.",
            },
        }
        if parent is not None:
            body["parent_asset_id"] = parent["asset_id"]
        return _ok(client.post(
            "/api/v1/security/assurance/model-risk/declarations",
            json=body,
        ))

    declare(system)
    declaration_a = declare(component_a, system)
    declaration_b = declare(component_b, component_a)

    cycle = client.patch(
        "/api/v1/security/assurance/model-risk/declarations/"
        + component_a["asset_id"],
        json={
            "expected_revision": declaration_a["revision"],
            "parent_asset_id": component_b["asset_id"],
        },
    )
    assert cycle.status_code == 422
    assert "cycle" in cycle.json()["detail"]

    approved_b = _ok(client.post(
        "/api/v1/security/assurance/model-risk/declarations/"
        + component_b["asset_id"]
        + "/review",
        json={
            "decision": "approved",
            "rationale": "Exact hierarchy and intended use reviewed.",
            "expected_revision": declaration_b["revision"],
        },
    ))
    detached = _ok(client.patch(
        "/api/v1/security/assurance/model-risk/declarations/"
        + component_b["asset_id"],
        json={
            "expected_revision": approved_b["revision"],
            "parent_asset_id": None,
        },
    ))
    assert detached["parent_asset_id"] is None
    assert detached["status"] == "proposed"
    assert detached["review"] is None


def test_real_portfolio_api_snapshot_integrity_and_http_errors():
    _enable_portfolio()
    report = _ok(client.get(
        "/api/v1/security/assurance/portfolio-risk/report"
    ))
    period = report["period_id"]
    snapshot = _ok(client.post(
        "/api/v1/security/assurance/portfolio-risk/snapshots",
        json={"expected_revision": 0, "period_id": period},
    ))
    assert snapshot["report_sha256"] == snapshot["report"]["report_sha256"]
    loaded = _ok(client.get(
        f"/api/v1/security/assurance/portfolio-risk/snapshots/{period}"
    ))
    assert loaded["report_sha256"] == snapshot["report_sha256"]

    assert client.get(
        "/api/v1/security/assurance/portfolio-risk/snapshots/2099-Q1"
    ).status_code == 404
    assert client.get(
        "/api/v1/security/assurance/portfolio-risk/snapshots/2026-Q5"
    ).status_code == 422

    year, quarter_text = period.split("-Q")
    quarter = int(quarter_text)
    previous = (
        f"{int(year) - 1}-Q4" if quarter == 1 else f"{year}-Q{quarter - 1}"
    )
    closed = client.post(
        "/api/v1/security/assurance/portfolio-risk/snapshots",
        json={"expected_revision": 0, "period_id": previous},
    )
    assert closed.status_code == 409


def test_ai_inventory_api_requires_tenant_and_binds_admin_sync(monkeypatch):
    from maverick import ai_inventory

    calls: dict = {}
    monkeypatch.setattr(ai_inventory, "enabled", lambda: True)
    monkeypatch.setattr(
        ai_inventory,
        "available_connectors",
        lambda: ["bedrock", "vertex_ai"],
    )
    monkeypatch.setattr(
        ai_inventory,
        "get_ai_inventory_config",
        lambda: {
            "enable": True,
            "connectors": ["bedrock"],
            "limits": ai_inventory.DiscoveryLimits(
                page_cap=100,
                record_cap=5000,
                retry_attempts=3,
                timeout_seconds=30,
            ),
            "missing_grace_runs": 2,
        },
    )
    monkeypatch.setattr(
        ai_inventory,
        "list_discovered_assets",
        lambda **_kwargs: [{"asset_id": "MAA-" + ("a" * 32), "status": "present"}],
    )
    monkeypatch.setattr(
        ai_inventory,
        "list_discovery_runs",
        lambda **_kwargs: [{"id": "AIR-one", "status": "complete"}],
    )
    monkeypatch.setattr(
        ai_inventory,
        "connector_status",
        lambda name: {"connector": name, "state": "complete"},
    )

    assert client.get(
        "/api/v1/security/assurance/ai-inventory"
    ).status_code == 409
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    overview = _ok(client.get(
        "/api/v1/security/assurance/ai-inventory"
    ))
    assert overview["configured_connectors"] == ["bedrock"]
    assert overview["limits"]["record_cap"] == 5000
    assert overview["assets"][0]["status"] == "present"

    def sync(connector, *, actor):
        calls.update({"connector": connector, "actor": actor})
        return {"id": "AIR-two", "status": "complete", "asset_count": 1}

    monkeypatch.setattr(ai_inventory, "sync_connector", sync)
    result = _ok(client.post(
        "/api/v1/security/assurance/ai-inventory/connectors/bedrock/sync"
    ))
    assert result["status"] == "complete"
    assert calls == {"connector": "bedrock", "actor": "local:dashboard"}
    assert client.post(
        "/api/v1/security/assurance/ai-inventory/connectors/unknown/sync"
    ).status_code == 422


def test_ai_inventory_configuration_failure_is_service_unavailable(monkeypatch):
    from maverick import ai_inventory

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(ai_inventory, "enabled", lambda: True)
    monkeypatch.setattr(
        ai_inventory,
        "available_connectors",
        lambda: ["bedrock"],
    )

    def unavailable_config():
        raise ai_inventory.AIInventoryConfigError(
            "required credential reference is unavailable"
        )

    monkeypatch.setattr(
        ai_inventory,
        "get_ai_inventory_config",
        unavailable_config,
    )
    response = client.get("/api/v1/security/assurance/ai-inventory")
    assert response.status_code == 503
    assert response.json()["detail"] == (
        "required credential reference is unavailable"
    )


def test_policy_pack_http_lifecycle_requires_explicit_admin_actions(monkeypatch):
    from maverick import policy_packs
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls: dict = {}
    bundled = {
        "pack_id": "nist-ai-rmf-1.0-starter",
        "version": "1.0.0",
        "content_sha256": "a" * 64,
        "framework": {"name": "NIST AI RMF", "version": "1.0"},
        "control_count": 0,
    }
    monkeypatch.setattr(policy_packs, "enabled", lambda: True)
    monkeypatch.setattr(
        policy_packs,
        "bundled_summaries",
        lambda: {bundled["pack_id"]: bundled},
    )
    monkeypatch.setattr(
        policy_packs,
        "list_catalog",
        lambda: {"items": [], "count": 0, "truncated": False, "limit": 100},
    )
    monkeypatch.setattr(
        policy_packs,
        "list_channels",
        lambda: {"items": [], "count": 0, "truncated": False, "limit": 100},
    )
    monkeypatch.setattr(
        policy_packs,
        "list_subscriptions",
        lambda: {"items": [], "count": 0, "truncated": False, "limit": 100},
    )
    channel = {
        "pack_id": bundled["pack_id"],
        "pack_version": bundled["version"],
        "content_sha256": bundled["content_sha256"],
        "revision": 1,
    }
    monkeypatch.setattr(
        policy_packs,
        "get_channel_summary",
        lambda _pack_id: channel,
    )
    monkeypatch.setattr(
        policy_packs,
        "get_subscription_summary",
        lambda _pack_id: (
            {
                "id": "pps-one",
                "pack_id": bundled["pack_id"],
                "revision": 2 if "refresh" in calls else 1,
                "needs_refresh": False,
                "current_count": 0,
                "stale_count": 0,
                "missing_count": 0,
                "retired_count": 0,
            }
            if "subscribe" in calls
            else None
        ),
    )
    monkeypatch.setattr(
        policy_packs,
        "get_subscription_change_detail",
        lambda pack_id: (
            {
                "id": "pps-one",
                "pack_id": pack_id,
                "pack_version": bundled["version"],
                "pack_sha256": bundled["content_sha256"],
                "revision": 3 if "attest" in calls else 2,
                "last_diff": None,
                "controls": [{
                    "control_id": "CTRL-1",
                    "status": "current" if "attest" in calls else "missing",
                    "requirements_sha256": "b" * 64,
                    "previous_requirements_sha256": None,
                    "stale_reason": None,
                    "attestation_present": "attest" in calls,
                }],
                "retired_controls": [],
                "certification": False,
                "legal_advice": False,
            }
            if "subscribe" in calls
            else None
        ),
    )

    overview = _ok(client.get(
        "/api/v1/security/assurance/policy-packs"
    ))
    assert bundled["pack_id"] in overview["bundled"]
    assert "controls" not in overview["bundled"][bundled["pack_id"]]
    assert overview["certification"] is False
    detail = _ok(client.get(
        "/api/v1/security/assurance/policy-packs/"
        + bundled["pack_id"]
    ))
    assert detail["active_channel"]["content_sha256"] == "a" * 64
    assert "requirements" not in detail

    def stage(pack_id, *, actor):
        calls["stage"] = (pack_id, actor)
        return {"id": "ppk-one", "pack_id": pack_id, "revision": 1}

    def activate(entry_id, **kwargs):
        calls["activate"] = (entry_id, kwargs)
        return {"id": "ppc-one", "pack_id": bundled["pack_id"], "revision": 1}

    def subscribe(pack_id, *, actor):
        calls["subscribe"] = (pack_id, actor)
        return {"id": "pps-one", "pack_id": pack_id, "revision": 1}

    def refresh(subscription_id, **kwargs):
        calls["refresh"] = (subscription_id, kwargs)
        return {
            "id": subscription_id,
            "pack_id": bundled["pack_id"],
            "revision": 2,
        }

    def attest(subscription_id, control_id, **kwargs):
        calls["attest"] = (subscription_id, control_id, kwargs)
        return {
            "subscription": {
                "id": subscription_id,
                "pack_id": bundled["pack_id"],
                "revision": 3,
            },
            "idempotent": False,
        }

    monkeypatch.setattr(policy_packs, "stage_bundled", stage)
    monkeypatch.setattr(policy_packs, "activate_pack", activate)
    monkeypatch.setattr(policy_packs, "subscribe", subscribe)
    monkeypatch.setattr(policy_packs, "refresh_subscription", refresh)
    monkeypatch.setattr(policy_packs, "attest_control", attest)
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: "user:reviewer@example.test",
    )
    monkeypatch.setattr(
        policy_packs,
        "get_catalog_summary",
        lambda entry_id: {
            "id": entry_id,
            "pack_id": bundled["pack_id"],
            "pack_version": bundled["version"],
            "content_sha256": bundled["content_sha256"],
            "revision": 1,
        },
    )

    staged = _ok(client.post(
        "/api/v1/security/assurance/policy-packs/bundled/"
        + bundled["pack_id"]
        + "/stage"
    ), 201)
    _ok(client.post(
        f"/api/v1/security/assurance/policy-packs/catalog/{staged['id']}/activate",
        json={"expected_revision": 0},
    ))
    _ok(client.post(
        "/api/v1/security/assurance/policy-packs/"
        + bundled["pack_id"]
        + "/subscribe"
    ), 201)
    _ok(client.post(
        "/api/v1/security/assurance/policy-packs/subscriptions/pps-one/refresh",
        json={"expected_revision": 1},
    ))
    changes = _ok(client.get(
        "/api/v1/security/assurance/policy-packs/"
        + bundled["pack_id"]
        + "/changes"
    ))
    assert changes["controls"][0]["attestation_present"] is False
    attested = _ok(client.post(
        "/api/v1/security/assurance/policy-packs/subscriptions/pps-one/"
        "controls/CTRL-1/attest",
        json={
            "expected_revision": 2,
            "idempotency_key": "attest-ctrl-1",
            "evidence_bindings": [{
                "requirement_id": "REQ-1",
                "evidence_id": "MRE-evidence-one",
                "evidence_revision": 4,
                "evidence_sha256": "c" * 64,
            }],
        },
    ))
    assert attested["subscription"]["controls"][0]["attestation_present"] is True
    assert "attestation" not in attested
    assert calls["stage"][1] == "local:dashboard"
    assert calls["activate"][1]["admin"] is True
    assert calls["subscribe"][1] == "local:dashboard"
    assert calls["refresh"][1]["expected_revision"] == 1
    assert calls["attest"][2]["actor"] == "user:reviewer@example.test"
    assert calls["attest"][2]["evidence_bindings"][0]["evidence_revision"] == 4


def test_policy_subscription_http_requires_tenant_but_global_stage_does_not(
    monkeypatch,
):
    from maverick import policy_packs

    monkeypatch.setattr(policy_packs, "enabled", lambda: True)
    monkeypatch.setattr(
        policy_packs,
        "stage_bundled",
        lambda pack_id, *, actor: {
            "id": "ppk-global",
            "pack_id": pack_id,
            "revision": 1,
        },
    )
    monkeypatch.setattr(
        policy_packs,
        "get_catalog_summary",
        lambda entry_id: {
            "id": entry_id,
            "pack_id": "nist-ai-rmf-1.0-starter",
            "pack_version": "1.0.0",
            "content_sha256": "a" * 64,
            "revision": 1,
        },
    )

    for response in (
        client.get("/api/v1/security/assurance/policy-packs"),
        client.get(
            "/api/v1/security/assurance/policy-packs/nist-ai-rmf-1.0-starter",
        ),
        client.get(
            "/api/v1/security/assurance/policy-packs/"
            "nist-ai-rmf-1.0-starter/changes",
        ),
        client.post(
            "/api/v1/security/assurance/policy-packs/"
            "nist-ai-rmf-1.0-starter/subscribe",
        ),
        client.post(
            "/api/v1/security/assurance/policy-packs/subscriptions/pps-one/refresh",
            json={"expected_revision": 1},
        ),
        client.post(
            "/api/v1/security/assurance/policy-packs/subscriptions/pps-one/"
            "controls/CTRL-1/attest",
            json={
                "expected_revision": 1,
                "idempotency_key": "tenant-required",
                "evidence_bindings": [{
                    "requirement_id": "REQ-1",
                    "evidence_id": "MRE-evidence-one",
                    "evidence_revision": 1,
                    "evidence_sha256": "d" * 64,
                }],
            },
        ),
    ):
        assert response.status_code == 409
        assert "active tenant" in response.json()["detail"]

    staged = client.post(
        "/api/v1/security/assurance/policy-packs/bundled/"
        "nist-ai-rmf-1.0-starter/stage",
    )
    assert staged.status_code == 201
    assert staged.json()["id"] == "ppk-global"


def test_model_risk_http_flow_keeps_classification_and_review_human_governed():
    now = time.time()
    artifact_digest = hashlib.sha256(b"api-model-v1").hexdigest()
    observation = _ok(client.post(
        "/api/v1/security/assurance/model-risk/observations",
        json={
            "asset_type": "model",
            "source": "api_registry",
            "source_id": "customer-risk-model",
            "display_name": "Customer risk model",
            "version_digest": artifact_digest,
            "observed_at": now,
            "metadata": {"environment": "test"},
            "dependencies": [],
        },
    ))
    asset_id = observation["asset_id"]
    inventory = _ok(client.get(
        "/api/v1/security/assurance/model-risk/inventory"
    ))
    assert inventory["assets"][0]["asset_id"] == asset_id
    evaluator_digest = hashlib.sha256(b"api-evaluator-v1").hexdigest()
    evaluator = _ok(client.post(
        "/api/v1/security/assurance/model-risk/observations",
        json={
            "asset_type": "tool",
            "source": "api_registry",
            "source_id": "bounded-evaluator",
            "display_name": "Bounded evaluator",
            "version_digest": evaluator_digest,
            "observed_at": now,
            "metadata": {"environment": "test"},
            "dependencies": [],
        },
    ))

    declaration = _ok(client.post(
        "/api/v1/security/assurance/model-risk/declarations",
        json={
            "asset_id": asset_id,
            "owner": "AI Risk Committee",
            "purpose": "Decision support for trained reviewers.",
            "intended_use": "Advisory scoring with human review.",
            "risk_tier": "medium",
            "risk_context": {"human_oversight": True},
            "eu_ai_act": {"category": "undetermined"},
        },
    ))
    refused = client.post(
        f"/api/v1/security/assurance/model-risk/declarations/{asset_id}/review",
        json={
            "decision": "approved",
            "rationale": "This request has no human applicability assertion.",
            "expected_revision": declaration["revision"],
        },
    )
    assert refused.status_code == 422

    declaration = _ok(client.patch(
        f"/api/v1/security/assurance/model-risk/declarations/{asset_id}",
        json={
            "expected_revision": declaration["revision"],
            "eu_ai_act": {
                "category": "not_applicable",
                "asserted_at": now,
                "as_of": "2026-07-21",
                "source_ref": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
                "rationale": "A qualified human reviewed this test context.",
            },
        },
    ))
    declaration = _ok(client.post(
        f"/api/v1/security/assurance/model-risk/declarations/{asset_id}/review",
        json={
            "decision": "approved",
            "rationale": "Owner, use, risk context, and dated assertion reviewed.",
            "expected_revision": declaration["revision"],
        },
    ))
    assert declaration["status"] == "approved"
    assert declaration["legal_certification"] is False

    evidence = _ok(client.post(
        "/api/v1/security/assurance/model-risk/evidence",
        json={
            "asset_id": asset_id,
            "source_id": "evaluation-api-1",
            "evidence_kind": "evaluation",
            "result": "passed",
            "scope_digest": hashlib.sha256(b"evaluation-scope").hexdigest(),
            "artifact_digest": artifact_digest,
            "evaluator_digest": evaluator_digest,
            "evaluator_asset_id": evaluator["asset_id"],
            "summary": "Bounded evaluation receipt for the exact artifact.",
            "metrics": {"cases": 42, "pass_rate": 1.0},
            "observed_at": now,
            "valid_until": now + 3600,
        },
    ))
    approved = _ok(client.post(
        f"/api/v1/security/assurance/model-risk/evidence/{evidence['id']}/review",
        json={
            "decision": "approved",
            "rationale": "Scope, artifact binding, and result were reviewed.",
            "expected_revision": evidence["revision"],
        },
    ))
    assert approved["status"] == "approved"
    stale = client.post(
        f"/api/v1/security/assurance/model-risk/evidence/{evidence['id']}/review",
        json={
            "decision": "revoked",
            "rationale": "Stale browser state.",
            "expected_revision": evidence["revision"],
        },
    )
    assert stale.status_code == 409


def test_verified_training_receipt_route_uses_server_trust_and_active_tenant(
    monkeypatch,
):
    from maverick import model_risk_assurance
    from maverick.paths import current_tenant_id_strict

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls = {}

    def _record(asset_id, **kwargs):
        calls["tenant_id"] = current_tenant_id_strict()
        calls["asset_id"] = asset_id
        calls.update(kwargs)
        return {
            "id": "MRE-training-receipt",
            "evidence_kind": "training_run",
            "status": "pending_review",
        }

    monkeypatch.setattr(
        model_risk_assurance,
        "record_verified_training_receipt_evidence",
        _record,
    )
    valid_until = time.time() + 600
    response = _ok(client.post(
        "/api/v1/security/assurance/model-risk/evidence/training-receipts",
        json={
            "asset_id": "MAA-" + ("a" * 32),
            "receipt_id": "tenant-private-receipt-1",
            "actor": "local:dashboard",
            "valid_until": valid_until,
        },
    ))

    assert response["evidence_kind"] == "training_run"
    assert calls == {
        "tenant_id": "alpha",
        "asset_id": "MAA-" + ("a" * 32),
        "receipt_id": "tenant-private-receipt-1",
        "actor": "local:dashboard",
        "valid_until": valid_until,
    }


@pytest.mark.parametrize(
    "field",
    [
        "trusted_receipt_pubkeys",
        "trusted_approver_pubkeys",
    ],
)
def test_training_receipt_route_rejects_caller_supplied_trust_registries(
    monkeypatch,
    field,
):
    from maverick import model_risk_assurance

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(
        model_risk_assurance,
        "record_verified_training_receipt_evidence",
        lambda *_args, **_kwargs: pytest.fail("invalid input reached the officer"),
    )
    body = {
        "asset_id": "MAA-" + ("a" * 32),
        "receipt_id": "tenant-private-receipt-1",
        "actor": "local:dashboard",
        "valid_until": time.time() + 600,
    }
    body[field] = {"attacker-chosen": "trust-anchor"}
    response = client.post(
        "/api/v1/security/assurance/model-risk/evidence/training-receipts",
        json=body,
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("receipt", {"public_key": "11" * 32, "private_training_content": "raw"}),
        ("public_key", "11" * 32),
        ("private_key", "22" * 32),
        ("tenant_id", "different-tenant"),
    ],
)
def test_training_receipt_route_rejects_raw_self_disclosed_or_tenant_fields(
    monkeypatch,
    field,
    value,
):
    from maverick import model_risk_assurance

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(
        model_risk_assurance,
        "record_verified_training_receipt_evidence",
        lambda *_args, **_kwargs: pytest.fail("forbidden input reached the officer"),
    )
    body = {
        "asset_id": "MAA-" + ("a" * 32),
        "receipt_id": "tenant-private-receipt-1",
        "actor": "local:dashboard",
        "valid_until": time.time() + 600,
        field: value,
    }
    response = client.post(
        "/api/v1/security/assurance/model-risk/evidence/training-receipts",
        json=body,
    )
    assert response.status_code == 422


def test_training_receipt_route_requires_auth_and_binds_actor(monkeypatch):
    from maverick import model_risk_assurance

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "training-operator-token")
    monkeypatch.setattr(
        model_risk_assurance,
        "record_verified_training_receipt_evidence",
        lambda _asset_id, **_kwargs: {"status": "pending_review"},
    )
    body = {
        "asset_id": "MAA-" + ("a" * 32),
        "receipt_id": "tenant-private-receipt-1",
        "actor": "auth:dashboard-token",
        "valid_until": time.time() + 600,
    }
    path = "/api/v1/security/assurance/model-risk/evidence/training-receipts"
    assert client.post(path, json=body).status_code == 401

    headers = {
        "Authorization": "Bearer training-operator-token",
        "Origin": "http://127.0.0.1",
    }
    mismatched = dict(body, actor="impersonated:operator")
    assert client.post(path, json=mismatched, headers=headers).status_code == 403
    assert client.post(path, json=body, headers=headers).status_code == 200


def test_generic_evidence_route_refuses_unverified_training_run():
    now = time.time()
    response = client.post(
        "/api/v1/security/assurance/model-risk/evidence",
        json={
            "asset_id": "MAA-" + ("a" * 32),
            "source_id": "caller-asserted-receipt",
            "evidence_kind": "training_run",
            "result": "passed",
            "scope_digest": hashlib.sha256(b"scope").hexdigest(),
            "artifact_digest": hashlib.sha256(b"adapter").hexdigest(),
            "observed_at": now,
            "valid_until": now + 600,
        },
    )
    assert response.status_code == 422




def test_model_risk_assurance_page_is_available():
    response = client.get("/security/assurance")
    assert response.status_code == 200
    assert "Model risk &amp; AI assurance officer" in response.text


def test_ai_literacy_http_lifecycle_is_tenant_bound(monkeypatch):
    from maverick import ai_literacy

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls = []

    class Register:
        def list_requirements(self, **kwargs):
            calls.append(("list", kwargs))
            return [{"requirement_key": "safe-ai"}]

        def upsert_requirement(self, key, **kwargs):
            calls.append(("upsert", key, kwargs))
            return {"requirement_key": key, "revision": 1}

        def set_person_assignments(self, person_id, **kwargs):
            calls.append(("assignment", person_id, kwargs))
            return {"subject_ref": "PRN-one", "revision": 1}

        def get_person_assignment(self, person_id):
            calls.append(("get_assignment", person_id))
            return {"subject_ref": "PRN-one", "revision": 1}

        def record_completion(self, person_id, requirement_key, **kwargs):
            calls.append(("completion", person_id, requirement_key, kwargs))
            return {"id": "ALC-one"}

        def grant_waiver(self, person_id, requirement_key, **kwargs):
            calls.append(("waiver", person_id, requirement_key, kwargs))
            return {"id": "ALW-one", "revision": 1}

        def revoke_waiver(self, waiver_id, **kwargs):
            calls.append(("revoke", waiver_id, kwargs))
            return {"id": waiver_id, "status": "revoked"}

        def compute_gaps(self, person_id, **kwargs):
            calls.append(("gaps", person_id, kwargs))
            return {"subject_ref": "PRN-one", "summary": {"due": 0}}

        def list_completions(self, person_id):
            return [{"id": "ALC-one", "subject_ref": "PRN-one"}]

        def list_waivers(self, person_id):
            return [{"id": "ALW-one", "subject_ref": "PRN-one"}]

        def export_evidence(self, **kwargs):
            calls.append(("export", kwargs))
            return {"schema": "lightwork.ai-literacy-evidence-export.v1"}

    monkeypatch.setattr(ai_literacy, "enabled", lambda: True)
    monkeypatch.setattr(ai_literacy, "default_register", Register())
    monkeypatch.setattr(
        ai_literacy,
        "literacy_plane_status",
        lambda: {
            "authoritative_plane": "canonical",
            "reconciliation_required": True,
        },
    )
    base = "/api/v1/security/assurance/ai-literacy"
    requirement = {
        "title": "Safe AI operation",
        "role_ids": ["operator"],
        "system_ids": ["SYS-one"],
        "provider_id": "lms",
        "content_id": "safe-ai",
        "content_version": "v1",
        "validity_days": 365,
        "due_within_days": 30,
        "expected_revision": 0,
        "idempotency_key": "requirement-one",
    }
    assert _ok(client.put(f"{base}/requirements/safe-ai", json=requirement))["revision"] == 1
    assignment = {
        "role_ids": ["operator"],
        "system_ids": ["SYS-one"],
        "expected_revision": 0,
        "idempotency_key": "assignment-one",
    }
    _ok(client.put(f"{base}/people/person-one/assignment", json=assignment))
    _ok(client.get(f"{base}/people/person-one/assignment"))
    now = time.time()
    completion = {
        "provider_id": "lms",
        "content_id": "safe-ai",
        "content_version": "v1",
        "completed_at": now,
        "expires_at": now + 86400,
        "provider_evidence_sha256": "a" * 64,
        "provider_record_id": "record-one",
        "idempotency_key": "completion-one",
    }
    _ok(
        client.post(
            f"{base}/people/person-one/requirements/safe-ai/completions",
            json=completion,
        ),
        201,
    )
    waiver = {
        "kind": "waiver",
        "reviewer_id": "reviewer-one",
        "reason_code": "equivalent_training",
        "decision_basis_sha256": "b" * 64,
        "starts_at": now,
        "expires_at": now + 86400,
        "idempotency_key": "waiver-one",
    }
    _ok(
        client.post(
            f"{base}/people/person-one/requirements/safe-ai/waivers",
            json=waiver,
        ),
        201,
    )
    _ok(client.post(
        f"{base}/waivers/ALW-one/revoke",
        json={
            "reviewer_id": "reviewer-two",
            "expected_revision": 1,
            "idempotency_key": "revoke-one",
        },
    ))
    assert _ok(client.get(f"{base}/people/person-one/status"))["summary"] == {"due": 0}
    receipts = _ok(client.get(f"{base}/people/person-one/receipts"))
    assert receipts["completions"][0]["id"] == "ALC-one"
    assert _ok(client.post(
        f"{base}/evidence-export",
        json={"person_ids": ["person-one"]},
    ))["schema"].endswith("evidence-export.v1")
    assert _ok(client.get(f"{base}/requirements"))["count"] == 1
    plane = _ok(client.get(f"{base}/plane-status"))
    assert plane == {
        "authoritative_plane": "canonical",
        "reconciliation_required": True,
    }
    assert next(item for item in calls if item[0] == "upsert")[2]["actor"] == "local:dashboard"


def test_ai_literacy_employee_numbers_are_bounded_like_the_export(monkeypatch):
    from maverick import ai_literacy

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    looked_up = []

    class Register:
        def compute_gaps(self, person_id, **_kwargs):
            looked_up.append(person_id)
            return {"summary": {}}

    monkeypatch.setattr(ai_literacy, "enabled", lambda: True)
    monkeypatch.setattr(ai_literacy, "default_register", Register())
    base = "/api/v1/security/assurance/ai-literacy/people"

    assert client.get(f"{base}/{'7' * 129}/status").status_code == 422
    assert client.get(f"{base}/{'7' * 129}/assignment").status_code == 422
    assert client.get(f"{base}/{'7' * 129}/receipts").status_code == 422
    assert client.put(f"{base}/{'7' * 129}/assignment", json={
        "role_ids": [], "system_ids": [], "expected_revision": 0, "idempotency_key": "one",
    }).status_code == 422
    assert looked_up == []
    _ok(client.get(f"{base}/{'7' * 128}/status"))
    assert looked_up == ["7" * 128]


@pytest.mark.parametrize(
    ("reference", "status"),
    [
        ("has spaces", 422),
        ("-starts-with-a-dash", 422),
        ("x" * 129, 422),
        ("line\nbreak", 422),
        # A well-formed reference passes the form check and reaches the
        # workspace check (no workspace is active here).
        ("DE-2026/0042", 409),
        ("x" * 128, 409),
    ],
)
def test_article_73_filing_reference_is_checked_like_the_register(reference, status):
    response = client.post(
        "/api/v1/security/assurance/eu-ai-incidents/A73-one/reports/A73R-one/submission",
        json={
            "expected_revision": 4,
            "submission_reference": reference,
            "receipt_sha256": "b" * 64,
        },
    )

    assert response.status_code == status, response.text


def test_ai_business_intake_http_resume_and_submit(monkeypatch):
    from maverick import ai_business_intake as intake

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls = []

    def start(**kwargs):
        calls.append(("start", kwargs))
        return {"id": "ABI-one", "status": "draft", "revision": 1}

    def save(intake_id, **kwargs):
        calls.append(("save", intake_id, kwargs))
        return {"id": intake_id, "status": "draft", "revision": 2}

    def submit(intake_id, **kwargs):
        calls.append(("submit", intake_id, kwargs))
        return {"id": intake_id, "status": "pending_review", "revision": 3}

    monkeypatch.setattr(intake, "enabled", lambda: True)
    monkeypatch.setattr(intake, "start_intake", start)
    monkeypatch.setattr(intake, "save_intake", save)
    monkeypatch.setattr(intake, "submit_intake", submit)
    monkeypatch.setattr(
        intake,
        "get_intake",
        lambda intake_id, **_kwargs: {
            "id": intake_id,
            "status": "draft",
            "revision": 2,
            "submission": {"business_unit": "risk"},
        },
    )
    monkeypatch.setattr(
        intake,
        "list_intakes",
        lambda: [
            {"id": "ABI-one", "status": "draft"},
            {"id": "ABI-two", "status": "pending_review"},
        ],
    )
    base = "/api/v1/security/assurance/ai-business-intake"
    started = _ok(client.post(f"{base}/drafts", json={
        "idempotency_key": "intake-one",
        "initial": {"business_unit": "risk"},
    }), 201)
    assert started["revision"] == 1
    saved = _ok(client.patch(f"{base}/drafts/ABI-one", json={
        "patch": {"purpose": "internal decision support"},
        "operation_id": "save-one",
        "expected_revision": 1,
    }))
    assert saved["revision"] == 2
    resumed = _ok(client.get(f"{base}/drafts/ABI-one"))
    assert resumed["submission"] == {"business_unit": "risk"}
    submitted = _ok(client.post(f"{base}/drafts/ABI-one/submit", json={
        "operation_id": "submit-one",
        "expected_revision": 2,
    }))
    assert submitted["status"] == "pending_review"
    assert _ok(client.get(f"{base}/drafts"))["count"] == 2
    submissions = _ok(client.get(f"{base}/submissions"))
    assert submissions == {
        "submissions": [{"id": "ABI-two", "status": "pending_review"}],
        "count": 1,
    }
    assert calls[0][1]["actor"] == "local:dashboard"


def test_guided_intake_contract_uses_current_core_answers_and_context(monkeypatch):
    from maverick import ai_business_intake as intake

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(intake, "enabled", lambda: True)
    base = "/api/v1/security/assurance/ai-business-intake"
    response = client.get(base + "/form")
    form = _ok(response)
    assert response.headers["Cache-Control"] == "no-store"
    assert form["can_edit"] is True
    assert len(form["context"]) == 64
    assert {field["path"] for field in form["fields"] if field["required"]} == set(intake._REQUIRED_LEAVES)
    for field in form["fields"]:
        for choice in field.get("choices") or []:
            parts = field["path"].split(".")
            value = [choice] if field["kind"] == "multiple" else choice
            patch = {parts[0]: {parts[1]: value}} if len(parts) == 2 else {parts[0]: value}
            assert intake._normalize_patch(patch)
    calls = []
    monkeypatch.setattr(intake, "start_intake", lambda **kwargs: calls.append(kwargs) or {"id": "unused"})
    monkeypatch.setenv("MAVERICK_TENANT", "beta")
    denied = client.post(base + "/drafts", headers={"X-Lightwork-Intake-Context": form["context"]},
                         json={"idempotency_key": "stable-ref", "initial": {"use_case_name": "Test"}})
    assert denied.status_code == 409
    assert calls == []


def test_guided_intake_list_is_paged_and_permissions_remain_authoritative(monkeypatch):
    from maverick import ai_business_intake as intake
    from maverick_dashboard import auth

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(intake, "enabled", lambda: True)
    monkeypatch.setattr(intake, "list_intakes", lambda: [
        {"id": "ABI-first", "use_case_name": "Support assistant", "status": "draft"},
        {"id": "ABI-second", "use_case_name": "Support review", "status": "pending_review"},
        {"id": "ABI-third", "use_case_name": "Other", "status": "draft"},
    ])
    base = "/api/v1/security/assurance/ai-business-intake"
    monkeypatch.setattr(auth, "has_permission", lambda request, permission: permission == "view")
    form = _ok(client.get(base + "/form"))
    assert form["can_edit"] is False
    headers = {"X-Lightwork-Intake-Context": form["context"]}
    first = _ok(client.get(base + "/drafts?limit=1&q=support", headers=headers))
    second = _ok(client.get(base + "/drafts?limit=1&q=support&offset=1", headers=headers))
    assert first["count"] == 2 and first["has_more"] is True
    assert second["intakes"][0]["id"] == "ABI-second" and second["has_more"] is False
    assert first["context"] == form["context"]
    assert client.post(base + "/drafts", headers=headers, json={"idempotency_key": "test"}).status_code == 403


def test_ai_cost_roi_http_batch_reports_and_assumptions(monkeypatch):
    from maverick import ai_cost_roi as cost

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls = []

    class Service:
        def ingest(self, batch, **kwargs):
            calls.append(("ingest", batch, kwargs))
            return {"receipt_id": "ACR-one", "observation_count": len(batch.records)}

        def list_receipts(self):
            return [{"id": "ACR-one", "status": "complete"}]

        def portfolio_report(self, **kwargs):
            calls.append(("portfolio", kwargs))
            return {
                "scope": {"kind": "portfolio", "id": ""},
                "currency_conversion": "not_performed",
                "currencies": [{"currency": "USD", "measured_cost": "12.5"}],
            }

        def department_report(self, department, **kwargs):
            return {"scope": {"kind": "department", "id": department}}

        def asset_report(self, asset_id, **kwargs):
            return {"scope": {"kind": "asset", "id": asset_id}}

        def upsert_roi_assumption(self, **kwargs):
            calls.append(("assumption", kwargs))
            return {"id": "ARA-one", "scenario": kwargs["scenario"], "revision": 1}

    service = Service()
    monkeypatch.setattr(cost, "enabled", lambda: True)
    monkeypatch.setattr(cost, "default_service", service)
    base = "/api/v1/security/assurance/ai-cost-roi"
    batch = {
        "provider": "aws",
        "collector_id": "aws-export",
        "source_account_id": "payer-one",
        "batch_id": "batch-one",
        "period_start": "2026-08-01T00:00:00Z",
        "period_end": "2026-09-01T00:00:00Z",
        "collected_at": time.time(),
        "complete": True,
        "manifest_citation": {
            "uri": "s3://billing-evidence/manifest.json",
            "sha256": "a" * 64,
        },
        "records": [{
            "source_record_id": "line-one",
            "period_start": "2026-08-01T00:00:00Z",
            "period_end": "2026-08-02T00:00:00Z",
            "currency": "USD",
            "cost": "12.50",
            "usage": [{"metric": "tokens", "quantity": "1000", "unit": "count"}],
            "service": "Bedrock",
            "resource_id": "arn:aws:bedrock:us-east-1:123:model/one",
            "citation": {
                "uri": "s3://billing-evidence/export.parquet",
                "sha256": "b" * 64,
                "row_ref": "row-one",
            },
            "region": "us-east-1",
        }],
    }
    receipt = _ok(client.post(f"{base}/observations/batches", json=batch), 201)
    assert receipt["observation_count"] == 1
    assert calls[0][1].records[0].provider.value == "aws"
    assert calls[0][2]["actor"] == "local:dashboard"
    query = (
        "?period_start=2026-08-01T00%3A00%3A00Z"
        "&period_end=2026-09-01T00%3A00%3A00Z"
    )
    portfolio = _ok(client.get(f"{base}/portfolio{query}"))
    assert portfolio["currency_conversion"] == "not_performed"
    assert _ok(client.get(f"{base}/departments/risk{query}"))["scope"]["id"] == "risk"
    asset_id = "MAA-" + ("c" * 32)
    assert _ok(client.get(f"{base}/assets/{asset_id}{query}"))["scope"]["id"] == asset_id
    assert _ok(client.get(f"{base}/receipts"))["count"] == 1
    assumption = _ok(client.put(f"{base}/roi-assumptions/base-case", json={
        "scope_kind": "portfolio",
        "scope_id": "",
        "period_start": "2026-08-01T00:00:00Z",
        "period_end": "2026-09-01T00:00:00Z",
        "currency": "USD",
        "assumed_benefit": "25.00",
        "methodology": "Operator-entered avoided-cost estimate.",
        "rationale": "Decision-support scenario; not measured benefit.",
        "citations": [{
            "uri": "urn:lightwork:operator-assumption:one",
            "sha256": "d" * 64,
        }],
        "idempotency_key": "assumption-one",
        "expected_revision": 0,
    }))
    assert assumption["scenario"] == "base-case"
    invalid_correction = dict(batch)
    invalid_correction["batch_id"] = "correction-one"
    response = client.post(f"{base}/corrections", json=invalid_correction)
    assert response.status_code == 422


def test_ai_cost_report_requires_one_scenario_and_never_adds_alternatives(monkeypatch):
    from maverick import ai_cost_roi as cost

    monkeypatch.setenv("MAVERICK_TENANT", "roi-scenarios")
    monkeypatch.setattr(cost, "enabled", lambda: True)
    base = "/api/v1/security/assurance/ai-cost-roi"
    period = {"period_start": "2026-08-01T00:00:00Z", "period_end": "2026-09-01T00:00:00Z"}
    for scenario, amount in (("optimistic", "100"), ("pessimistic", "10")):
        _ok(client.put(f"{base}/roi-assumptions/{scenario}", json={
            **period, "scope_kind": "portfolio", "scope_id": "", "currency": "USD",
            "assumed_benefit": amount, "methodology": "Operator planning estimate.",
            "rationale": "Alternative scenarios, not additive measured results.",
            "citations": [{"uri": "urn:lightwork:assumption:" + scenario, "sha256": "d" * 64}],
            "idempotency_key": scenario, "expected_revision": 0,
        }))
    ambiguous = client.get(f"{base}/portfolio", params=period)
    assert ambiguous.status_code == 422, ambiguous.text
    assert "select a scenario" in ambiguous.json()["detail"]
    selected = _ok(client.get(f"{base}/portfolio", params={**period, "scenario": "pessimistic"}))
    assert selected["currencies"][0]["assumed_benefit"] == "10"
    assert selected["currencies"][0]["assumption_bindings"][0]["scenario"] == "pessimistic"


def test_ai_cost_collector_status_and_manual_collection_are_human_bound(monkeypatch):
    from maverick import ai_cost_roi as cost
    from maverick.ai_cost_collectors import CollectorLimits, CollectorSchedule
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls = []

    class Collector:
        provider = cost.BillingProvider.AWS
        collector_id = "aws_cost_explorer_v1"

    collector = Collector()

    class Service:
        def collect_and_ingest(self, selected, collection_request, *, actor):
            calls.append((selected, collection_request, actor))
            return {
                "receipt_id": "ACR-collected",
                "provider": selected.provider.value,
                "observation_count": 3,
            }

    runtime = {
        "collectors": (collector,),
        "schedule": CollectorSchedule(poll_seconds=86400, lookback_days=1),
        "limits": CollectorLimits(record_cap=750),
    }
    monkeypatch.setattr(cost, "enabled", lambda: True)
    monkeypatch.setattr(cost, "default_service", Service())
    monkeypatch.setattr(model_risk_api, "_ai_cost_collector_runtime", lambda: runtime)
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: "user:cost-admin@example.test",
    )
    base = "/api/v1/security/assurance/ai-cost-roi"

    status = _ok(client.get(f"{base}/collectors"))
    assert status["collectors"] == [{
        "provider": "aws",
        "collector_id": "aws_cost_explorer_v1",
    }]
    assert status["credentials_exposed"] is False
    assert status["limits"]["record_cap"] == 750
    assert "credential" not in str(status["collectors"]).lower()

    receipt = _ok(client.post(f"{base}/collectors/aws/collect", json={
        "period_start": "2026-08-26T00:00:00Z",
        "period_end": "2026-08-27T00:00:00Z",
        "max_records": 500,
    }))
    assert receipt["receipt_id"] == "ACR-collected"
    assert calls[0][0] is collector
    assert calls[0][1].max_records == 500
    assert calls[0][2] == "user:cost-admin@example.test"
    assert client.post(f"{base}/collectors/azure/collect", json={
        "period_start": "2026-08-26T00:00:00Z",
        "period_end": "2026-08-27T00:00:00Z",
    }).status_code == 403
    assert client.post(f"{base}/collectors/not-a-provider/collect", json={
        "period_start": "2026-08-26T00:00:00Z",
        "period_end": "2026-08-27T00:00:00Z",
    }).status_code == 422


def test_article_73_http_lifecycle_requires_human_authority(monkeypatch):
    from maverick import eu_ai_incidents
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls = []

    class Register:
        def open_incident(self, title, **kwargs):
            calls.append(("open", title, kwargs))
            return {"id": "A73-one"}

        def list_safe(self, **kwargs):
            return [{"incident_id": "A73-one", "status": "triage"}]

        def safe_projection(self, incident_id):
            return {"incident_id": incident_id, "status": "routed"}

        def record_routing_decision(self, incident_id, **kwargs):
            calls.append(("route", incident_id, kwargs))
            return {"id": incident_id}

        def draft_report(self, incident_id, **kwargs):
            calls.append(("draft", incident_id, kwargs))
            return {"id": incident_id}

        def approve_report(self, incident_id, report_id, **kwargs):
            calls.append(("approve", incident_id, report_id, kwargs))
            return {"id": incident_id}

        def record_submission(self, incident_id, report_id, **kwargs):
            calls.append(("submit", incident_id, report_id, kwargs))
            return {"id": incident_id}

        def get_report_payload(self, incident_id, report_id):
            return {"incident_id": incident_id, "report_id": report_id}

    register = Register()
    monkeypatch.setattr(eu_ai_incidents, "enabled", lambda: True)
    monkeypatch.setattr(eu_ai_incidents, "open_incident", register.open_incident)
    monkeypatch.setattr(eu_ai_incidents, "list_incidents", register.list_safe)
    monkeypatch.setattr(
        eu_ai_incidents,
        "get_safe_projection",
        register.safe_projection,
    )
    monkeypatch.setattr(
        eu_ai_incidents,
        "record_routing_decision",
        register.record_routing_decision,
    )
    monkeypatch.setattr(eu_ai_incidents, "draft_report", register.draft_report)
    monkeypatch.setattr(eu_ai_incidents, "approve_report", register.approve_report)
    monkeypatch.setattr(
        eu_ai_incidents,
        "record_submission",
        register.record_submission,
    )
    monkeypatch.setattr(
        eu_ai_incidents,
        "get_report_payload",
        register.get_report_payload,
    )
    monkeypatch.setattr(
        model_risk_api,
        "_article_73_authority_binding",
        lambda _request: (
            eu_ai_incidents.HumanAuthority("user:alice", "legal_counsel"),
            ["DE-authority"],
        ),
    )
    base = "/api/v1/security/assurance/eu-ai-incidents"
    now = time.time()
    opened = _ok(client.post(base, json={
        "title": "Serious incident triage",
        "asset_id": "SYS-one",
        "asset_version": "deployment-one",
        "awareness_at": now,
        "summary": "A human must determine Article 73 applicability.",
        "occurred_at": now - 60,
        "operator_role": "provider",
        "asserted_high_risk": "yes",
        "asserted_union_market": "yes",
        "incident_member_states": ["DE"],
        "outcomes": ["serious_harm_to_health"],
        "causality": "reasonable_likelihood",
        "evidence_refs": [{"id": "evidence-one", "sha256": "a" * 64}],
    }), 201)
    assert opened["incident_id"] == "A73-one"
    _ok(client.post(f"{base}/A73-one/routing", json={
        "decision": "report_to_authority",
        "threshold_determination": "met",
        "applicability_determination": "applies",
        "rationale": "Counsel confirmed the recorded route.",
        "expected_revision": 1,
    }))
    _ok(client.post(f"{base}/A73-one/reports", json={
        "kind": "initial",
        "details": {},
        "expected_revision": 2,
    }), 201)
    _ok(client.post(f"{base}/A73-one/reports/A73R-one/approve", json={
        "expected_revision": 3,
    }))
    _ok(client.post(f"{base}/A73-one/reports/A73R-one/submission", json={
        "expected_revision": 4,
        "submission_reference": "authority-receipt-one",
        "receipt_sha256": "b" * 64,
        "submitted_at": now + 10,
    }))
    assert _ok(client.get(f"{base}/A73-one/reports/A73R-one/payload"))["report_id"] == "A73R-one"
    assert _ok(client.get(base))["count"] == 1
    assert _ok(client.get(f"{base}/report-template"))["kind"] == "initial"
    route = next(item for item in calls if item[0] == "route")
    assert route[2]["authority"].principal == "user:alice"
    assert route[2]["authority"].role == "legal_counsel"


def test_grc_outbound_http_preview_state_and_events(monkeypatch):
    from dataclasses import dataclass
    from types import SimpleNamespace

    from maverick import grc_outbound_sync as grc
    from maverick import grc_vendor_transports, model_risk_assurance
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls = []
    delivered = {}
    finding = {
        "id": "finding-one",
        "asset_id": "asset-one",
        "severity": "high",
        "summary": "Evidence is stale.",
        "finding_type": "stale_evidence",
        "finding_sha256": "a" * 64,
    }

    class Service:
        def preview(self, source, *, target):
            calls.append(("preview", source, target))
            return {
                "target": target.value,
                "source_kind": source.kind.value,
                "payload_sha256": "c" * 64,
                "idempotency_key": "grc-key-one",
            }

        def get_state(self, **kwargs):
            calls.append(("state", kwargs))
            return dict(delivered) or None

        def sync(self, source, *, target, transport, actor):
            calls.append(("sync", source, target, transport, actor))
            delivered.update({
                "status": "delivered",
                "idempotency_key": "grc-key-one",
                "source": {"kind": source.kind.value, "id": source.source_id,
                           "revision": source.source_revision,
                           "digest": source.source_digest},
                "receipt": {"status": "accepted", "idempotency_key": "grc-key-one",
                            "source_revision": source.source_revision,
                            "source_digest": source.source_digest},
            })
            return dict(delivered)

        def list_events(self, **kwargs):
            return [{"category": "transport_failure"}]

    @dataclass(frozen=True)
    class Limits:
        timeout_seconds: float = 10.0

    service = Service()
    transport = SimpleNamespace(
        _base_url="https://irm.example.test",
        _credential_secret_ref="secret:grc",  # pragma: allowlist secret -- reference name, not a value
        _limits=Limits(),
        _http=object(),
    )
    monkeypatch.setattr(grc, "enabled", lambda: True)
    monkeypatch.setattr(grc, "configured_sync", lambda: service)
    monkeypatch.setattr(
        grc,
        "policy_from_config",
        lambda: SimpleNamespace(allowed_targets=(grc.GRCSystem.SERVICENOW_IRM,)),
    )
    monkeypatch.setattr(
        grc_vendor_transports,
        "transport_from_config",
        lambda _target, **_kwargs: transport,
    )
    monkeypatch.setattr(model_risk_assurance, "findings", lambda **_kwargs: [dict(finding)])
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: "user:grc-admin@example.test",
    )
    base = "/api/v1/security/assurance/grc-outbound"
    # The browser names only the record; every sent value is resolved from
    # the current native record on the server.
    body = {"source_kind": "finding", "source_id": "finding-one"}
    assert client.post(f"{base}/servicenow_irm/preview", json={
        **body, "summary": "Typed by the browser."}).status_code == 422
    preview = _ok(client.post(f"{base}/servicenow_irm/preview", json=body))
    assert preview["technical"]["target"] == "servicenow_irm"
    assert {"label": "Complete summary", "value": "Evidence is stale."} in preview["details"]
    review = {"review_token": preview["review_token"]}
    # Nothing is sent without an explicit confirmation of the reviewed record.
    assert client.post(f"{base}/servicenow_irm/sync", json=review).status_code == 409
    assert not any(item[0] == "sync" for item in calls)
    synced = _ok(client.post(f"{base}/servicenow_irm/sync", json={**review, "confirmed": True}))
    assert synced["status"] == "delivered"
    state = _ok(client.get(f"{base}/servicenow_irm/finding/finding-one"))
    assert state["status"] == "delivered"
    assert _ok(client.get(f"{base}/events"))["count"] == 1
    previewed = next(item[1] for item in calls if item[0] == "preview")
    assert previewed.source_id == "finding-one"
    assert previewed.summary == "Evidence is stale."
    sync_call = next(item for item in calls if item[0] == "sync")
    # The configured transport is wrapped so each physical request rechecks
    # the reviewed record, and the send is attributed to the human.
    assert sync_call[3] is not transport
    assert transport._http.__class__.__name__ == "CheckedHTTP"
    assert sync_call[4] == "user:grc-admin@example.test"


def test_dynamic_risk_http_lifecycle_is_tenant_and_human_bound(monkeypatch):
    from maverick import ai_dynamic_risk as risk
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls = []
    asset_id = "MAA-" + ("d" * 32)

    class Service:
        def current_score(self, selected_asset_id):
            return {"asset_id": selected_asset_id, "score": 72.0, "risk_tier": "high"}

        def list_signals(self, selected_asset_id):
            return [{"id": "DRS-one", "asset_id": selected_asset_id}]

        def get_signal(self, signal_id):
            return {"id": signal_id, "asset_id": asset_id, "revision": 1}

        def ingest_signal(self, signal, *, actor):
            calls.append(("ingest", signal, actor))
            return {"id": "DRS-one", "asset_id": signal.asset_id, "revision": 1}

        def resolve_signal(self, signal_id, **kwargs):
            calls.append(("resolve", signal_id, kwargs))
            return {"id": signal_id, "status": "resolved", "revision": 2}

        def supersede_signal(self, signal_id, **kwargs):
            calls.append(("supersede", signal_id, kwargs))
            return {"id": signal_id, "status": "superseded", "revision": 2}

        def score_asset(self, selected_asset_id, **kwargs):
            calls.append(("score", selected_asset_id, kwargs))
            return {"asset_id": selected_asset_id, "score": 72.0, "risk_tier": "high"}

    monkeypatch.setattr(risk, "enabled", lambda: True)
    monkeypatch.setattr(risk, "default_service", Service())
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: "user:risk-admin@example.test",
    )
    base = "/api/v1/security/assurance/dynamic-risk"
    now = time.time()
    signal = _ok(client.post(f"{base}/signals", json={
        "asset_id": asset_id,
        "category": "privacy",
        "severity": 80.0,
        "confidence": 0.9,
        "observed_at": now,
        "expires_at": now + 3600,
        "source_type": "telemetry",
        "source_id": "privacy-monitor-one",
        "source_digest": "a" * 64,
        "signal_code": "pii.detected",
        "idempotency_key": "signal-one",
    }), 201)
    assert signal["id"] == "DRS-one"
    assert _ok(client.get(f"{base}/assets/{asset_id}"))["risk_tier"] == "high"
    assert _ok(client.get(f"{base}/assets/{asset_id}/signals"))["count"] == 1
    assert _ok(client.get(f"{base}/signals/DRS-one"))["revision"] == 1
    _ok(client.post(f"{base}/signals/DRS-one/resolve", json={
        "expected_revision": 1,
        "resolution_code": "control.remediated",
        "resolution_evidence_digest": "b" * 64,
    }))
    _ok(client.post(f"{base}/signals/DRS-two/supersede", json={
        "expected_revision": 1,
        "superseding_signal_id": "DRS-three",
    }))
    scored = _ok(client.post(f"{base}/assets/{asset_id}/score", json={
        "expected_revision": 0,
        "asset_criticality": "high",
        "eu_risk_tier": "high",
        "sensitive_data": "personal",
        "external_exposure": "public",
    }))
    assert scored["score"] == 72.0
    assert calls[0][1].asset_id == asset_id
    assert calls[0][2].principal == "user:risk-admin@example.test"
    assert calls[-1][2]["context"].external_exposure == "public"


def test_operational_ai_policy_http_lifecycle_and_four_eyes_actor(monkeypatch):
    from maverick import ai_policy_management as policy
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    calls = []

    class Service:
        def list_policies(self):
            return [{"policy_id": "runtime-use", "status": "active"}]

        def get_policy(self, policy_id):
            return {"policy_id": policy_id, "status": "active", "revision": 2}

        def create_policy(self, policy_id, **kwargs):
            calls.append(("create", policy_id, kwargs))
            return {"policy_id": policy_id, "status": "draft", "revision": 1}

        def add_policy_version(self, policy_id, **kwargs):
            calls.append(("version", policy_id, kwargs))
            return {"policy_id": policy_id, "status": "active", "revision": 3}

        def activate_policy(self, policy_id, version, **kwargs):
            calls.append(("activate", policy_id, version, kwargs))
            return {"policy_id": policy_id, "active_version": version, "revision": 2}

        def list_exceptions(self):
            return [{"exception_key": "exception-one", "status": "approved"}]

        def get_exception(self, exception_key):
            return {"exception_key": exception_key, "status": "approved", "revision": 2}

        def request_exception(self, exception_key, **kwargs):
            calls.append(("request", exception_key, kwargs))
            return {"exception_key": exception_key, "status": "pending", "revision": 1}

        def approve_exception(self, exception_key, **kwargs):
            calls.append(("approve", exception_key, kwargs))
            return {"exception_key": exception_key, "status": "approved", "revision": 2}

        def close_exception(self, exception_key, **kwargs):
            calls.append(("close", exception_key, kwargs))
            return {"exception_key": exception_key, "status": "closed", "revision": 3}

        def preview(self, context):
            calls.append(("preview", context))
            return {"final_effect": "restrict", "required_control_ids": ["CTRL-1"]}

        def list_evaluations(self):
            return [{"evaluation_key": "eval-one", "revalidation_required": False}]

        def get_evaluation(self, evaluation_key):
            return {"evaluation_key": evaluation_key, "revision": 1}

        def evaluate(self, evaluation_key, context, **kwargs):
            calls.append(("evaluate", evaluation_key, context, kwargs))
            return {"evaluation_key": evaluation_key, "revision": 1}

        def attest_evaluation(self, evaluation_key, **kwargs):
            calls.append(("attest", evaluation_key, kwargs))
            return {"evaluation_key": evaluation_key, "revision": 2}

    service = Service()
    monkeypatch.setattr(policy, "enabled", lambda: True)
    monkeypatch.setattr(policy, "configured_policy_management", lambda: service)
    actors = iter([
        "user:activator@example.test",
        "user:requester@example.test",
        "user:approver@example.test",
        "user:closer@example.test",
        "user:attestor@example.test",
    ])
    monkeypatch.setattr(model_risk_api, "_human_principal", lambda _request: next(actors))
    base = "/api/v1/security/assurance/ai-policy-management"
    statement = {
        "statement_id": "external-pii",
        "text": "Restrict public use of personal data.",
        "effect": "restrict",
        "applicability": {"risk_tiers": ["high"], "data_classes": ["personal"]},
        "required_control_ids": ["CTRL-1"],
    }
    created = _ok(client.post(f"{base}/policies", json={
        "policy_id": "runtime-use",
        "title": "Runtime use",
        "description": "Operational controls.",
        "statements": [statement],
    }), 201)
    assert created["status"] == "draft"
    assert _ok(client.get(f"{base}/policies"))["count"] == 1
    assert _ok(client.get(f"{base}/policies/runtime-use"))["revision"] == 2
    _ok(client.post(f"{base}/policies/runtime-use/versions", json={
        "title": "Runtime use v2",
        "description": "Tightened controls.",
        "statements": [statement],
        "expected_revision": 2,
    }))
    _ok(client.post(f"{base}/policies/runtime-use/activate", json={
        "version": 1,
        "expected_revision": 1,
    }))
    requested = _ok(client.post(f"{base}/exceptions", json={
        "exception_key": "exception-one",
        "policy_id": "runtime-use",
        "policy_version": 1,
        "scope": {"asset_ids": ["asset-one"], "statement_ids": ["external-pii"]},
        "reason": "Temporary migration with compensating review.",
        "compensating_control_ids": ["CTRL-MANUAL-REVIEW"],
        "expires_at": time.time() + 3600,
    }), 201)
    assert requested["status"] == "pending"
    _ok(client.post(f"{base}/exceptions/exception-one/approve", json={
        "expected_revision": 1,
    }))
    assert _ok(client.get(f"{base}/exceptions"))["count"] == 1
    assert _ok(client.get(f"{base}/exceptions/exception-one"))["status"] == "approved"
    _ok(client.post(f"{base}/exceptions/exception-one/close", json={
        "expected_revision": 2,
        "reason": "Migration finished.",
    }))
    context = {
        "asset_id": "asset-one",
        "risk_tier": "high",
        "jurisdictions": ["us"],
        "data_classes": ["personal"],
        "deployment_types": ["production"],
        "asset_types": ["agent"],
        "tags": ["external"],
        "use_case_tags": ["support"],
    }
    assert _ok(client.post(f"{base}/preview", json={"context": context}))[
        "final_effect"
    ] == "restrict"
    _ok(client.post(f"{base}/evaluations", json={
        "evaluation_key": "eval-one",
        "context": context,
        "expected_revision": 0,
    }))
    assert _ok(client.get(f"{base}/evaluations"))["count"] == 1
    assert _ok(client.get(f"{base}/evaluations/eval-one"))["revision"] == 1
    _ok(client.post(f"{base}/evaluations/eval-one/attest", json={
        "expected_revision": 1,
    }))
    assert next(item for item in calls if item[0] == "activate")[3]["actor"] == (
        "user:activator@example.test"
    )
    assert next(item for item in calls if item[0] == "request")[2]["requester"] == (
        "user:requester@example.test"
    )
    assert next(item for item in calls if item[0] == "approve")[2]["approver"] == (
        "user:approver@example.test"
    )


def test_runtime_guardrail_http_uses_current_declaration_and_records_risk(monkeypatch):
    from maverick import ai_dynamic_risk as risk
    from maverick import ai_runtime_guardrails as runtime
    from maverick import model_risk_assurance as assurance

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    asset_id = "MAA-" + ("e" * 32)
    digest = "f" * 64
    captured = []
    ingested = []

    class RuntimeService:
        def evaluate(self, request):
            captured.append(request)
            return runtime.RuntimeGuardrailResult(
                decision="block",
                redacted_content=None,
                receipt={
                    "stage": "prompt",
                    "decision": "block",
                    "categories": ["policy"],
                    "rule_ids": ["policy/use/prohibit"],
                    "control_ids": [],
                    "input_sha256": "1" * 64,
                    "output_sha256": "2" * 64,
                    "policy_sha256": "3" * 64,
                    "evaluated_at": 1_800_000_000.0,
                    "asset_binding": {
                        "tenant_ref": "TEN-" + ("4" * 24),
                        "asset_id": asset_id,
                        "asset_revision": 4,
                        "asset_version_digest": digest,
                    },
                },
            )

    class RiskService:
        def ingest_signal(self, signal, *, actor):
            ingested.append((signal, actor))
            return {"signal_id": "DRS-runtime", "revision": 1}

    monkeypatch.setattr(runtime, "enabled", lambda: True)
    monkeypatch.setattr(runtime, "default_service", RuntimeService())
    monkeypatch.setattr(
        runtime,
        "dynamic_risk_receipt",
        lambda _result: {"schema": "normalized-runtime-risk"},
    )
    monkeypatch.setattr(assurance, "enabled", lambda: True)
    monkeypatch.setattr(
        assurance,
        "get_observation",
        lambda _asset_id: {
            "asset_id": asset_id,
            "revision": 4,
            "version_digest": digest,
            "identity": {"asset_type": "system"},
        },
    )
    monkeypatch.setattr(
        assurance,
        "get_declaration",
        lambda _asset_id: {
            "asset_id": asset_id,
            "status": "approved",
            "observed_version_digest": digest,
            "risk_tier": "critical",
            "risk_context": {"jurisdictions": ["eu"]},
        },
    )
    monkeypatch.setattr(risk, "enabled", lambda: True)
    monkeypatch.setattr(risk, "default_service", RiskService())
    monkeypatch.setattr(risk, "signal_from_runtime_receipt", lambda value: value)

    raw = "do not persist this prompt"
    response = client.post(
        "/api/v1/security/assurance/runtime-guardrails/evaluate",
        json={
            "stage": "prompt",
            "content": raw,
            "asset_id": asset_id,
            "asset_revision": 4,
            "asset_version_digest": digest,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "block"
    assert body["dynamic_risk_signal"] == {
        "status": "recorded",
        "signal_id": "DRS-runtime",
        "signal_revision": 1,
    }
    assert raw not in response.text
    assert captured[0].policy_context.risk_tier == "critical"
    assert captured[0].policy_context.jurisdictions == ("eu",)
    assert ingested[0][1].principal == "system:runtime-guardrails"


def test_ai_explainability_http_lifecycle_is_closed_and_human_bound(monkeypatch):
    from maverick import ai_explainability as explainability
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    asset_id = "MAA-" + ("9" * 32)
    captured = []

    class Service:
        def list_explanations(self, selected_asset_id=None):
            return [{"explanation_id": "AIX-" + ("1" * 32), "asset_id": selected_asset_id}]

        def get_explanation(self, explanation_id):
            return {"explanation_id": explanation_id, "revision": 1}

        def ingest_receipt(self, receipt, *, actor):
            captured.append(("ingest", receipt, actor))
            return {
                "explanation_id": "AIX-" + ("1" * 32),
                "status": "pending_review",
                "revision": 1,
            }

        def review_explanation(self, explanation_id, **kwargs):
            captured.append(("review", explanation_id, kwargs))
            return {
                "explanation_id": explanation_id,
                "status": "reviewed",
                "revision": 2,
            }

    service = Service()
    monkeypatch.setattr(explainability, "enabled", lambda: True)
    monkeypatch.setattr(
        explainability,
        "configured_explainability",
        lambda: service,
    )
    principals = iter([
        "user:explanation-owner@example.test",
        "user:independent-reviewer@example.test",
    ])
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: next(principals),
    )

    base = "/api/v1/security/assurance/ai-explainability/explanations"
    receipt = {
        "schema": "lightwork.ai-explainability-normalized-shap-receipt.v1",
        "method": "shap",
        "asset_id": asset_id,
        "asset_revision": 3,
        "asset_version_digest": "a" * 64,
        "receipt_id": "provider-receipt-1",
        "observed_at": time.time(),
        "input_sha256": "b" * 64,
        "output_sha256": "c" * 64,
        "explainer_sha256": "d" * 64,
        "source_sha256": "e" * 64,
        "contributions": [
            {
                "factor_code": "account_age",
                "direction": "positive",
                "magnitude": 0.8,
            }
        ],
        "counterfactuals": [],
        "receipt_sha256": "f" * 64,
    }

    assert _ok(client.get(base, params={"asset_id": asset_id}))["count"] == 1
    explanation_id = "AIX-" + ("1" * 32)
    assert _ok(client.get(f"{base}/{explanation_id}"))["revision"] == 1
    admitted = _ok(client.post(base, json=receipt), 201)
    assert admitted["status"] == "pending_review"
    reviewed = _ok(client.post(
        f"{base}/{explanation_id}/review",
        json={
            "expected_revision": 1,
            "outcome": "accepted",
            "evidence_sha256": "0" * 64,
        },
    ))
    assert reviewed["status"] == "reviewed"
    assert captured[0][1]["schema"] == receipt["schema"]
    assert "receipt_schema" not in captured[0][1]
    assert captured[0][2].principal == "user:explanation-owner@example.test"
    assert captured[1][2]["actor"].principal == (
        "user:independent-reviewer@example.test"
    )

    with_raw_values = {
        **receipt,
        "provider_payload": {"feature_value": "must-not-enter"},
    }
    assert client.post(base, json=with_raw_values).status_code == 422
    wrong_schema = {
        **receipt,
        "schema": "lightwork.ai-explainability-normalized-lime-receipt.v1",
    }
    assert client.post(base, json=wrong_schema).status_code == 422


def test_ai_insurability_http_lifecycle_keeps_human_and_export_boundaries(monkeypatch):
    from maverick import ai_insurability as insurability
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    captured = []

    class Service:
        def list_profiles(self, *, limit):
            captured.append(("list", limit))
            return [{"profile_id": "insurer-packet", "status": "draft"}]

        def get_profile(self, profile_id):
            return {"profile_id": profile_id, "status": "draft", "revision": 1}

        def create_profile(self, profile_id, **kwargs):
            captured.append(("create", profile_id, kwargs))
            return {"profile_id": profile_id, "status": "draft", "revision": 1}

        def add_version(self, profile_id, **kwargs):
            captured.append(("version", profile_id, kwargs))
            return {"profile_id": profile_id, "status": "draft", "revision": 2}

        def approve_profile(self, profile_id, version, **kwargs):
            captured.append(("approve", profile_id, version, kwargs))
            return {"profile_id": profile_id, "status": "approved", "revision": 3}

        def export_profile(self, profile_id, *, version=None):
            captured.append(("export", profile_id, version))
            return {
                "profile_id": profile_id,
                "version": version,
                "claims": {"insurer_acceptance_claim": False},
            }

    service = Service()
    monkeypatch.setattr(insurability, "enabled", lambda: True)
    monkeypatch.setattr(insurability, "configured_insurability", lambda: service)
    principals = iter([
        "user:profile-preparer@example.test",
        "user:profile-versioner@example.test",
        "user:profile-approver@example.test",
    ])
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: next(principals),
    )

    base = "/api/v1/security/assurance/ai-insurability/profiles"
    asset_id = "MAA-" + ("7" * 32)
    content = {
        "governance_posture": {},
        "measurements": {},
        "incident_summary": {},
        "open_findings_summary": {},
        "safeguards": [],
        "exclusions": [],
        "limitations": [],
        "verifier_instructions": {},
    }
    creation = {
        "profile_id": "insurer-packet",
        "asset_id": asset_id,
        "content": content,
        "evidence_bindings": [{"evidence_id": "MRE-one", "digest": "a" * 64}],
        "idempotency_key": "prepare-profile-1",
    }
    assert _ok(client.get(base, params={"limit": 10}))["count"] == 1
    assert _ok(client.get(f"{base}/insurer-packet"))["revision"] == 1
    assert _ok(client.post(base, json=creation), 201)["status"] == "draft"
    assert _ok(client.post(f"{base}/insurer-packet/versions", json={
        "content": content,
        "evidence_bindings": creation["evidence_bindings"],
        "expected_revision": 1,
        "idempotency_key": "prepare-profile-2",
    }))["revision"] == 2
    assert _ok(client.post(f"{base}/insurer-packet/approve", json={
        "version": 2,
        "expected_revision": 2,
    }))["status"] == "approved"
    exported = _ok(client.get(
        f"{base}/insurer-packet/export",
        params={"version": 2},
    ))
    assert exported["claims"]["insurer_acceptance_claim"] is False
    assert next(item for item in captured if item[0] == "create")[2]["actor"] == (
        "user:profile-preparer@example.test"
    )
    assert next(item for item in captured if item[0] == "approve")[3]["actor"] == (
        "user:profile-approver@example.test"
    )
    assert client.post(base, json={**creation, "raw_prompts": ["secret"]}).status_code == 422


def test_ai_conformity_http_exposes_human_gated_readiness_not_legal_effect(monkeypatch):
    from maverick import ai_conformity_workflow as conformity
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    captured = []
    case_id = "EUC-" + ("2" * 32)

    class Service:
        def list_case_projections(self, *, limit):
            captured.append(("list", limit))
            return [{"case_id": case_id, "workflow_status": "draft"}]

        def project_case(self, selected_case_id):
            return {"case_id": selected_case_id, "revision": 1}

        def create_case(self, **kwargs):
            captured.append(("create", kwargs))
            return {"case_id": case_id, "revision": 1}

        def bind_evidence(self, selected_case_id, **kwargs):
            captured.append(("evidence", selected_case_id, kwargs))
            return {"binding_id": "EUE-" + ("3" * 32)}

        def set_fria_determination(self, selected_case_id, **kwargs):
            captured.append(("fria", selected_case_id, kwargs))
            return {"case_id": selected_case_id, "revision": 2}

        def set_article_43_route(self, selected_case_id, **kwargs):
            captured.append(("route", selected_case_id, kwargs))
            return {"case_id": selected_case_id, "revision": 3}

        def set_checklist_entry(self, selected_case_id, **kwargs):
            captured.append(("checklist", selected_case_id, kwargs))
            return {"case_id": selected_case_id, "revision": 4}

        def submit_case(self, selected_case_id, **kwargs):
            captured.append(("submit", selected_case_id, kwargs))
            return {"case_id": selected_case_id, "workflow_status": "submitted"}

        def approve_case(self, selected_case_id, **kwargs):
            captured.append(("approve", selected_case_id, kwargs))
            return {"case_id": selected_case_id, "workflow_status": "approved"}

        def export_package(self, selected_case_id):
            return {
                "case_id": selected_case_id,
                "legal_effects": {"certification": False, "ce_marking": False},
            }

    service = Service()
    monkeypatch.setattr(conformity, "enabled", lambda: True)
    monkeypatch.setattr(
        conformity,
        "configured_ai_conformity_workflow",
        lambda: service,
    )
    principals = iter([f"user:conformity-{index}" for index in range(7)])
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: next(principals),
    )

    base = "/api/v1/security/assurance/ai-conformity/cases"
    source = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727"
    citation = {"provision": "Article 6 and Annex III", "official_url": source}
    asset_id = "MAA-" + ("6" * 32)
    assert _ok(client.get(base))["count"] == 1
    assert _ok(client.get(f"{base}/{case_id}"))["revision"] == 1
    assert _ok(client.post(base, json={
        "asset_id": asset_id,
        "economic_operator_role": "provider",
        "risk_tier": "high_risk",
        "act_applicability": "applicable",
        "legal_basis": [citation],
        "operation_id": "create-case-1",
    }), 201)["case_id"] == case_id
    binding = _ok(client.post(f"{base}/{case_id}/evidence", json={
        "evidence_type": "fria",
        "source_ref": "MRE-approved-evidence",
        "sha256": "a" * 64,
        "operation_id": "bind-evidence-1",
    }), 201)
    _ok(client.post(f"{base}/{case_id}/fria-determination", json={
        "outcome": "required",
        "rationale_sha256": "b" * 64,
        "citations": [citation],
        "expected_revision": 1,
        "operation_id": "fria-1",
    }))
    _ok(client.post(f"{base}/{case_id}/article-43-route", json={
        "route": "internal_control_annex_vi",
        "rationale_sha256": "c" * 64,
        "citations": [citation],
        "expected_revision": 2,
        "operation_id": "route-1",
    }))
    _ok(client.post(f"{base}/{case_id}/checklist", json={
        "domain": "fria",
        "section": "1a_deployer_process",
        "status": "complete",
        "evidence_binding_ids": [binding["binding_id"]],
        "rationale_sha256": None,
        "citations": [],
        "expected_revision": 3,
        "operation_id": "check-1",
    }))
    assert _ok(client.post(f"{base}/{case_id}/submit", json={
        "expected_revision": 4,
        "operation_id": "submit-1",
    }))["workflow_status"] == "submitted"
    assert _ok(client.post(f"{base}/{case_id}/approve", json={
        "expected_revision": 5,
        "operation_id": "approve-1",
    }))["workflow_status"] == "approved"
    exported = _ok(client.get(f"{base}/{case_id}/export"))
    assert exported["legal_effects"] == {"certification": False, "ce_marking": False}
    assert next(item for item in captured if item[0] == "create")[1][
        "actor"
    ].principal_ref == "user:conformity-0"
    assert next(item for item in captured if item[0] == "approve")[2][
        "actor"
    ].principal_ref == "user:conformity-6"


def test_regulated_vertical_http_lifecycle_is_aggregate_and_human_bound(monkeypatch):
    from maverick import ai_regulated_verticals as regulated
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    captured = []

    class Service:
        def list_packages(self, *, limit):
            return [{"package_id": "fair-lending-1", "status": "draft", "limit": limit}]

        def get_package(self, package_id):
            return {"package_id": package_id, "revision": 1}

        def create_package(self, package_id, **kwargs):
            captured.append(("create", package_id, kwargs))
            return {"package_id": package_id, "status": "draft", "revision": 1}

        def add_version(self, package_id, **kwargs):
            captured.append(("version", package_id, kwargs))
            return {"package_id": package_id, "status": "draft", "revision": 2}

        def approve_package(self, package_id, version, **kwargs):
            captured.append(("approve", package_id, version, kwargs))
            return {"package_id": package_id, "status": "approved", "revision": 3}

        def export_package(self, package_id, *, version=None):
            return {
                "package_id": package_id,
                "version": version,
                "privacy": {"individual_records_included": False},
                "claims": {"regulator_filing_claim": False},
            }

    service = Service()
    monkeypatch.setattr(regulated, "enabled", lambda: True)
    monkeypatch.setattr(
        regulated,
        "configured_regulated_verticals",
        lambda: service,
    )
    principals = iter(["user:vertical-preparer", "user:vertical-versioner", "user:vertical-approver"])
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: next(principals),
    )

    base = "/api/v1/security/assurance/ai-regulated-verticals/packages"
    content = {"aggregate_report": {"state": "missing"}}
    creation = {
        "package_id": "fair-lending-1",
        "package_type": "fair_lending_aggregate",
        "asset_id": "MAA-" + ("5" * 32),
        "content": content,
        "evidence_bindings": [],
        "idempotency_key": "vertical-1",
    }
    assert _ok(client.get(base))["count"] == 1
    assert _ok(client.get(f"{base}/fair-lending-1"))["revision"] == 1
    assert _ok(client.post(base, json=creation), 201)["status"] == "draft"
    assert _ok(client.post(f"{base}/fair-lending-1/versions", json={
        "content": content,
        "evidence_bindings": [],
        "expected_revision": 1,
        "idempotency_key": "vertical-2",
    }))["revision"] == 2
    assert _ok(client.post(f"{base}/fair-lending-1/approve", json={
        "version": 2,
        "expected_revision": 2,
    }))["status"] == "approved"
    exported = _ok(client.get(
        f"{base}/fair-lending-1/export",
        params={"version": 2},
    ))
    assert exported["privacy"]["individual_records_included"] is False
    assert exported["claims"]["regulator_filing_claim"] is False
    assert next(item for item in captured if item[0] == "approve")[3]["actor"] == (
        "user:vertical-approver"
    )
    assert client.post(
        base,
        json={**creation, "individual_records": [{"person": "forbidden"}]},
    ).status_code == 422


def test_bank_mrm_http_lifecycle_preserves_package_integrity_scope(monkeypatch):
    from maverick import ai_bank_mrm as bank_mrm
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    captured = []

    class Service:
        def list_packages(self, *, limit):
            return [{"package_id": "bank-model-1", "status": "draft", "limit": limit}]

        def get_package(self, package_id):
            return {"package_id": package_id, "revision": 1}

        def create_package(self, package_id, **kwargs):
            captured.append(("create", package_id, kwargs))
            return {"package_id": package_id, "status": "draft", "revision": 1}

        def add_version(self, package_id, **kwargs):
            captured.append(("version", package_id, kwargs))
            return {"package_id": package_id, "status": "draft", "revision": 2}

        def approve_package(self, package_id, version, **kwargs):
            captured.append(("approve", package_id, version, kwargs))
            return {"package_id": package_id, "status": "approved", "revision": 3}

        def export_package(self, package_id, *, version=None):
            return {
                "package_id": package_id,
                "version": version,
                "approval": {"scope": "package-integrity-only"},
                "claims": {"model_approved": False, "regulatory_acceptance": False},
            }

    service = Service()
    monkeypatch.setattr(bank_mrm, "enabled", lambda: True)
    monkeypatch.setattr(bank_mrm, "configured_bank_mrm", lambda: service)
    principals = iter(["user:bank-preparer", "user:bank-versioner", "user:bank-approver"])
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: next(principals),
    )

    base = "/api/v1/security/assurance/ai-bank-mrm/packages"
    content = {
        name: {"schema": "lightwork.ai-bank-mrm-section.v1", "state": "missing"}
        for name in (
            "inventory_classification",
            "validation_scope",
            "validation_results",
            "conceptual_soundness",
            "outcomes_monitoring",
            "limitations",
            "change_controls",
            "issues_remediation",
            "independent_review",
        )
    }
    creation = {
        "package_id": "bank-model-1",
        "asset_id": "MAA-" + ("4" * 32),
        "content": content,
        "evidence_bindings": [],
        "idempotency_key": "bank-mrm-1",
    }
    assert _ok(client.get(base))["count"] == 1
    assert _ok(client.get(f"{base}/bank-model-1"))["revision"] == 1
    assert _ok(client.post(base, json=creation), 201)["revision"] == 1
    assert _ok(client.post(f"{base}/bank-model-1/versions", json={
        "content": content,
        "evidence_bindings": [],
        "expected_revision": 1,
        "idempotency_key": "bank-mrm-2",
    }))["revision"] == 2
    assert _ok(client.post(f"{base}/bank-model-1/approve", json={
        "version": 2,
        "expected_revision": 2,
    }))["status"] == "approved"
    exported = _ok(client.get(
        f"{base}/bank-model-1/export",
        params={"version": 2},
    ))
    assert exported["approval"]["scope"] == "package-integrity-only"
    assert exported["claims"]["model_approved"] is False
    assert exported["claims"]["regulatory_acceptance"] is False
    assert next(item for item in captured if item[0] == "approve")[3]["actor"] == (
        "user:bank-approver"
    )
    assert client.post(
        base,
        json={**creation, "raw_model_output": "forbidden"},
    ).status_code == 422


def test_ai_benchmark_http_is_voluntary_aggregate_only_and_human_bound(monkeypatch):
    from maverick import ai_benchmark_exchange as benchmark
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    captured = []
    contribution_id = "BCI-" + ("1" * 32)
    report_id = "BXR-" + ("2" * 32)

    class Service:
        def list_contributions(self, *, limit):
            return [{"contribution_id": contribution_id, "limit": limit}]

        def get_contribution(self, selected_id):
            return {"contribution_id": selected_id, "revision": 1}

        def create_contribution(self, selected_id, **kwargs):
            captured.append(("create", selected_id, kwargs))
            return {"contribution_id": selected_id, "status": "draft", "revision": 1}

        def add_version(self, selected_id, **kwargs):
            captured.append(("version", selected_id, kwargs))
            return {"contribution_id": selected_id, "status": "draft", "revision": 2}

        def approve_contribution(self, selected_id, version, **kwargs):
            captured.append(("approve", selected_id, version, kwargs))
            return {"contribution_id": selected_id, "status": "approved", "revision": 3}

        def export_contribution(self, selected_id, *, version=None):
            return {
                "contribution_id": selected_id,
                "version": version,
                "privacy": {
                    "raw_records_included": False,
                    "anonymous": False,
                    "differential_privacy_verified": False,
                },
            }

        def submit_contribution_to_coordinator(self, selected_id, **kwargs):
            captured.append(("submit", selected_id, kwargs))
            return {
                "schema": "lightwork.ai-benchmark-coordinator-receipt.v1",
                "status": "accepted",
                "receipt_id": "BCR-" + ("9" * 32),
                "packet_sha256": "d" * 64,
            }

        def list_cohort_reports(self, *, limit):
            return [{"report_id": report_id, "limit": limit}]

        def get_cohort_report(self, selected_id):
            return {"report_id": selected_id, "revision": 1}

        def ingest_cohort_report(self, report, *, actor):
            captured.append(("report", report, actor))
            return {"report_id": report["report_id"], "signature_verified": True}

    service = Service()
    monkeypatch.setattr(benchmark, "enabled", lambda: True)
    monkeypatch.setattr(
        benchmark,
        "configured_benchmark_exchange",
        lambda: service,
    )
    principals = iter(
        [
            "user:benchmark-preparer",
            "user:benchmark-versioner",
            "user:benchmark-approver",
            "user:benchmark-submitter",
            "user:benchmark-report-admitter",
        ]
    )
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: next(principals),
    )

    base = "/api/v1/security/assurance/ai-benchmark"
    content = {
        "metric_code": "control_coverage_rate",
        "numerator": 8,
        "denominator": 10,
        "period": {"start": "2026-01-01", "end": "2026-03-31"},
        "cohort": {
            "industry_code": "technology",
            "geography_code": "north_america",
            "organization_size_code": "midsize",
            "model_modality_code": "text",
        },
        "evidence_bindings": [{"evidence_id": "MRE-one", "digest": "a" * 64}],
        "voluntary_opt_in": True,
        "idempotency_key": "benchmark-v1",
    }
    creation = {"contribution_id": contribution_id, **content}
    assert _ok(client.get(f"{base}/contributions"))["count"] == 1
    assert _ok(client.get(f"{base}/contributions/{contribution_id}"))["revision"] == 1
    assert _ok(client.post(f"{base}/contributions", json=creation), 201)["revision"] == 1
    assert _ok(client.post(f"{base}/contributions/{contribution_id}/versions", json={
        **content,
        "idempotency_key": "benchmark-v2",
        "expected_revision": 1,
    }))["revision"] == 2
    assert _ok(client.post(f"{base}/contributions/{contribution_id}/approve", json={
        "version": 2,
        "expected_revision": 2,
    }))["status"] == "approved"
    exported = _ok(client.get(
        f"{base}/contributions/{contribution_id}/export",
        params={"version": 2},
    ))
    assert exported["privacy"] == {
        "raw_records_included": False,
        "anonymous": False,
        "differential_privacy_verified": False,
    }
    submitted = _ok(client.post(
        f"{base}/contributions/{contribution_id}/submit",
        json={
            "explicit_consent": True,
            "idempotency_key": "benchmark-submit-v2",
            "version": 2,
        },
    ))
    assert submitted["status"] == "accepted"
    report = {
        "schema": "lightwork.ai-benchmark-cohort-report.v1",
        "report_id": report_id,
        "issued_at": time.time(),
        **{key: content[key] for key in ("metric_code", "numerator", "denominator", "period", "cohort")},
        "contributor_count": 7,
        "k_anonymity_min": 5,
        "aggregation_method": "pooled_ratio",
        "privacy": {
            "state": "not_dp",
            "epsilon": None,
            "delta": None,
            "noise_mechanism": None,
        },
        "methodology_version": "benchmark-aggregate-v1",
        "report_sha256": "b" * 64,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": "KEY-" + ("3" * 32),
            "value": "c" * 64,
        },
    }
    assert _ok(client.get(f"{base}/cohort-reports"))["count"] == 1
    assert _ok(client.get(f"{base}/cohort-reports/{report_id}"))["revision"] == 1
    assert _ok(client.post(f"{base}/cohort-reports", json=report), 201)[
        "signature_verified"
    ] is True
    assert next(item for item in captured if item[0] == "create")[2]["actor"] == (
        "user:benchmark-preparer"
    )
    assert next(item for item in captured if item[0] == "approve")[3]["actor"] == (
        "user:benchmark-approver"
    )
    assert next(item for item in captured if item[0] == "submit")[2] == {
        "explicit_consent": True,
        "idempotency_key": "benchmark-submit-v2",
        "version": 2,
    }
    assert next(item for item in captured if item[0] == "report")[2] == (
        "user:benchmark-report-admitter"
    )
    assert client.post(
        f"{base}/contributions/{contribution_id}/versions",
        json={**content, "contribution_id": contribution_id, "expected_revision": 1},
    ).status_code == 422
    assert client.post(
        f"{base}/contributions",
        json={**creation, "raw_examples": ["forbidden"]},
    ).status_code == 422


def test_ai_discovery_sensor_http_is_closed_digest_bound_control_plane(monkeypatch):
    from maverick import ai_discovery_sensors as discovery
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    captured = []
    sensor_id = "DSN-" + ("4" * 32)
    observation_id = "DSO-" + ("5" * 32)

    class Service:
        def list_sensors(self, *, limit):
            return [{"sensor_id": sensor_id, "limit": limit}]

        def get_sensor(self, selected_id):
            return {"sensor_id": selected_id, "revision": 1}

        def register_sensor(self, **kwargs):
            captured.append(("register", kwargs))
            return {"sensor_id": sensor_id, "status": "pending_approval", "revision": 1}

        def approve_sensor(self, selected_id, **kwargs):
            captured.append(("approve", selected_id, kwargs))
            return {"sensor_id": selected_id, "status": "active", "revision": 2}

        def prepare_sensor_configuration(self, selected_id, **kwargs):
            captured.append(("configuration", selected_id, kwargs))
            return {"sensor_id": selected_id, "status": "pending_approval", "revision": 3}

        def request_sensor_revocation(self, selected_id, **kwargs):
            captured.append(("revocation", selected_id, kwargs))
            return {"sensor_id": selected_id, "status": "revocation_pending", "revision": 4}

        def approve_sensor_revocation(self, selected_id, **kwargs):
            captured.append(("revoke-approve", selected_id, kwargs))
            return {"sensor_id": selected_id, "status": "revoked", "revision": 5}

        def ingest_observation(self, selected_id, **kwargs):
            captured.append(("observation", selected_id, kwargs))
            return {"observation_id": observation_id, "revision": 1}

        def list_observations(self, *, limit):
            return [{"observation_id": observation_id, "limit": limit}]

        def get_observation(self, selected_id):
            return {"observation_id": selected_id, "revision": 1}

        def aggregate_findings(self):
            return {
                "complete_discovery_claim": False,
                "findings": [{"provider_code": "openai", "count": 1}],
            }

    service = Service()
    monkeypatch.setattr(discovery, "enabled", lambda: True)
    monkeypatch.setattr(discovery, "default_service", lambda: service)
    principals = iter(
        [
            "user:sensor-preparer",
            "user:sensor-approver",
            "user:sensor-configurer",
            "user:sensor-revoker",
            "user:sensor-revocation-approver",
        ]
    )
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: next(principals),
    )

    base = "/api/v1/security/assurance/ai-discovery-sensors"
    assert _ok(client.get(f"{base}/sensors"))["count"] == 1
    assert _ok(client.get(f"{base}/sensors/{sensor_id}"))["revision"] == 1
    assert _ok(client.post(f"{base}/sensors", json={
        "sensor_name": "browser-one",
        "sensor_type": "browser_extension",
        "config_sha256": "a" * 64,
    }), 201)["status"] == "pending_approval"
    assert _ok(client.post(f"{base}/sensors/{sensor_id}/approve", json={
        "expected_revision": 1,
    }))["status"] == "active"
    assert _ok(client.post(f"{base}/sensors/{sensor_id}/configuration", json={
        "config_sha256": "b" * 64,
        "expected_revision": 2,
    }))["status"] == "pending_approval"
    assert _ok(client.post(f"{base}/sensors/{sensor_id}/revocation", json={
        "reason_code": "retired",
        "expected_revision": 3,
    }))["status"] == "revocation_pending"
    assert _ok(client.post(f"{base}/sensors/{sensor_id}/revocation/approve", json={
        "expected_revision": 4,
    }))["status"] == "revoked"
    observation = {
        "sensor_revision": 1,
        "config_sha256": "a" * 64,
        "event_sha256": "c" * 64,
        "observed_at": time.time(),
        "ai_service_code": "chat",
        "ai_product_code": "assistant",
        "provider_code": "openai",
        "domain_category": "generative_ai",
        "deployment_type": "saas",
        "environment_code": "production",
        "context_codes": ["managed-device"],
    }
    assert _ok(client.post(
        f"{base}/sensors/{sensor_id}/observations",
        json=observation,
    ), 201)["observation_id"] == observation_id
    assert _ok(client.get(f"{base}/observations"))["count"] == 1
    assert _ok(client.get(f"{base}/observations/{observation_id}"))["revision"] == 1
    assert _ok(client.get(f"{base}/findings"))["complete_discovery_claim"] is False
    assert next(item for item in captured if item[0] == "register")[1][
        "actor"
    ].principal == "user:sensor-preparer"
    admitted = next(item for item in captured if item[0] == "observation")[2]
    assert admitted["observation"].provider_code == "openai"
    assert admitted["config_sha256"] == "a" * 64
    assert client.post(
        f"{base}/sensors/{sensor_id}/observations",
        json={**observation, "url": "https://forbidden.example"},
    ).status_code == 422


def test_ai_media_provenance_http_keeps_bytes_transient_and_c2pa_external(monkeypatch):
    from maverick import ai_media_provenance as provenance
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    captured = []
    provenance_id = "AMP-" + ("6" * 32)

    class SignedResult:
        media = b"signed-media-bytes"
        record = {
            "provenance_id": provenance_id,
            "content_sha256": "d" * 64,
        }

    class Service:
        def capability_status(self):
            return {
                "implementation": "external_adapter_required",
                "verification": {"status": "unsupported"},
                "signing": {"status": "unsupported"},
            }

        def list_records(self, *, asset_id=None):
            return [{"provenance_id": provenance_id, "asset_id": asset_id}]

        def get_record(self, selected_id):
            return {"provenance_id": selected_id, "revision": 1}

        def export_record(self, selected_id):
            return {
                "provenance_id": selected_id,
                "certification_claim": False,
                "coverage": {"media_bytes_persisted": False},
            }

        def ingest_verification_receipt(self, receipt, *, actor):
            captured.append(("verification-receipt", receipt, actor))
            return {"provenance_id": provenance_id, "operation": "verification"}

        def ingest_signing_receipt(self, receipt, *, actor):
            captured.append(("signing-receipt", receipt, actor))
            return {"provenance_id": provenance_id, "operation": "signing"}

        def verify_media(self, media, **kwargs):
            captured.append(("verify", media, kwargs))
            return {
                "provenance_id": provenance_id,
                "coverage": {"media_bytes_persisted": False},
            }

        def sign_media(self, media, **kwargs):
            captured.append(("sign", media, kwargs))
            return SignedResult()

        def prepare_release_record(self, selected_id, **kwargs):
            captured.append(("prepare", selected_id, kwargs))
            return {"provenance_id": selected_id, "status": "release_pending"}

        def review_release_record(self, selected_id, **kwargs):
            captured.append(("review", selected_id, kwargs))
            return {"provenance_id": selected_id, "status": "release_approved"}

    service = Service()
    monkeypatch.setattr(provenance, "enabled", lambda: True)
    monkeypatch.setattr(
        provenance,
        "configured_media_provenance",
        lambda: service,
    )
    principals = iter(
        [
            "user:receipt-verifier",
            "user:receipt-signer",
            "user:media-verifier",
            "user:media-signer",
            "user:release-preparer",
            "user:release-reviewer",
        ]
    )
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: next(principals),
    )

    base = "/api/v1/security/assurance/ai-media-provenance"
    capabilities = _ok(client.get(f"{base}/capabilities"))
    assert capabilities["implementation"] == "external_adapter_required"
    asset_id = "MAA-" + ("7" * 32)
    assert _ok(client.get(f"{base}/records", params={"asset_id": asset_id}))[
        "count"
    ] == 1
    assert _ok(client.get(f"{base}/records/{provenance_id}"))["revision"] == 1
    exported = _ok(client.get(f"{base}/records/{provenance_id}/export"))
    assert exported["certification_claim"] is False
    assert exported["coverage"]["media_bytes_persisted"] is False

    receipt = {
        "schema": "lightwork.c2pa-adapter-receipt.v1",
        "operation": "verification",
        "adapter_id": "c2pa.adapter",
        "adapter_version": "2.2.0",
        "standard": "c2pa/2.2",
        "receipt_id": "receipt-001",
        "observed_at": time.time(),
        "media_kind": "image",
        "source_content_sha256": "a" * 64,
        "content_sha256": "a" * 64,
        "asset_id": asset_id,
        "asset_revision": 2,
        "asset_version_digest": "b" * 64,
        "deployment_id": "production-east",
        "deployment_revision": 3,
        "deployment_artifact_digest": "b" * 64,
        "context_id": "public-release",
        "context_revision": 4,
        "context_digest": "c" * 64,
        "manifest_sha256": "d" * 64,
        "claim_generator": "External C2PA adapter",
        "signing_time": time.time() - 10,
        "validation_state": "valid",
        "assertion_codes": ["c2pa.actions", "c2pa.hash.data"],
        "trust_chain_state": "trusted",
        "receipt_sha256": "e" * 64,
    }
    assert _ok(client.post(
        f"{base}/receipts/verification",
        json=receipt,
    ), 201)["operation"] == "verification"
    signing_receipt = {
        **receipt,
        "operation": "signing",
        "receipt_id": "receipt-002",
        "content_sha256": "f" * 64,
    }
    assert _ok(client.post(
        f"{base}/receipts/signing",
        json=signing_receipt,
    ), 201)["operation"] == "signing"

    multipart = {
        "media_kind": "image",
        "asset_id": asset_id,
        "deployment_id": "production-east",
        "context_id": "public-release",
    }
    verified = _ok(client.post(
        f"{base}/verify",
        data=multipart,
        files={"file": ("image.png", b"transient-media", "image/png")},
    ), 201)
    assert verified["coverage"]["media_bytes_persisted"] is False
    signed = client.post(
        f"{base}/sign",
        data={**multipart, "assertion_codes": "c2pa.actions,c2pa.hash.data"},
        files={"file": ("image.png", b"transient-media", "image/png")},
    )
    assert signed.status_code == 200
    assert signed.content == b"signed-media-bytes"
    assert signed.headers["x-lightwork-provenance-id"] == provenance_id
    assert _ok(client.post(f"{base}/records/{provenance_id}/release", json={
        "expected_revision": 1,
        "purpose_code": "public_release",
        "evidence_sha256": "1" * 64,
    }))["status"] == "release_pending"
    assert _ok(client.post(f"{base}/records/{provenance_id}/review", json={
        "expected_revision": 2,
        "outcome": "approved",
        "evidence_sha256": "2" * 64,
    }))["status"] == "release_approved"
    assert next(item for item in captured if item[0] == "verify")[1] == (
        b"transient-media"
    )
    assert next(item for item in captured if item[0] == "sign")[2][
        "assertion_codes"
    ] == ["c2pa.actions", "c2pa.hash.data"]
    assert next(item for item in captured if item[0] == "review")[2][
        "actor"
    ].principal == "user:release-reviewer"
    assert client.post(
        f"{base}/receipts/verification",
        json={**receipt, "raw_media": "forbidden"},
    ).status_code == 422


def test_identity_governance_http_exposes_read_only_bounded_snapshots(monkeypatch):
    from maverick_dashboard import (
        identity_governance_runtime,
        identity_governance_scheduler,
        model_risk_api,
    )

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    section = {"enable": True, "entra": {"enable": True}}
    captured = []
    monkeypatch.setattr(
        model_risk_api,
        "_identity_governance_section",
        lambda: section,
    )
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: "user:identity-governance-operator",
    )
    monkeypatch.setattr(
        identity_governance_runtime,
        "connector_status",
        lambda selected, **_kwargs: {
            "enabled": selected is section,
            "supported_providers": ["entra", "okta", "purview"],
            "configured_providers": ["entra"],
            "transport": {"read_only": True},
            "live_acceptance_verified": False,
            "complete_inventory_claimed": False,
        },
    )
    monkeypatch.setattr(
        identity_governance_scheduler,
        "configured_scheduler_status",
        lambda selected: {
            "enabled": selected is section,
            "providers": [{"provider": "entra", "health": "never_run"}],
            "source_complete": False,
            "risk_generated": False,
        },
    )

    def scheduled(selected, *, actor):
        captured.append((selected, "scheduled", actor))
        return {
            "provider_count": 1,
            "results": [],
            "failures": [],
            "source_complete": False,
            "live_acceptance_verified": False,
        }

    monkeypatch.setattr(
        identity_governance_scheduler,
        "run_configured_collection",
        scheduled,
    )

    def collect(selected, provider):
        captured.append((selected, provider))
        if provider not in {"entra", "okta", "purview"}:
            raise ValueError("identity-governance provider is unsupported")
        return {
            "schema": "lightwork.identity_governance.snapshot.v1",
            "provider": provider,
            "tenant_sha256": "a" * 64,
            "identities": [{"identity_kind": "agent_identity"}],
            "grants": [],
            "data_classifications": [],
            "live_acceptance_verified": False,
            "complete_inventory_claimed": False,
        }

    monkeypatch.setattr(identity_governance_runtime, "collect_connector", collect)
    base = "/api/v1/security/assurance/identity-governance/connectors"
    status = _ok(client.get(base))
    assert status["transport"]["read_only"] is True
    assert status["configured_providers"] == ["entra"]
    assert status["live_acceptance_verified"] is False
    snapshot = _ok(client.post(f"{base}/entra/collect"))
    assert snapshot["provider"] == "entra"
    assert snapshot["identities"] == [{"identity_kind": "agent_identity"}]
    assert snapshot["complete_inventory_claimed"] is False
    assert captured == [(section, "entra")]
    assert client.post(f"{base}/unknown/collect").status_code == 422
    scheduler_base = "/api/v1/security/assurance/identity-governance/scheduler"
    scheduler_status = _ok(client.get(f"{scheduler_base}/status"))
    assert scheduler_status["source_complete"] is False
    scheduled_result = _ok(client.post(f"{scheduler_base}/run"))
    assert scheduled_result["provider_count"] == 1
    assert captured[-1] == (
        section,
        "scheduled",
        "user:identity-governance-operator",
    )


def test_identity_control_http_is_authenticated_default_off_and_unavailable(monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    section = {
        "enable": True,
        "entra": {"enable": True},
        "controls": {
            "enable": True,
            "federation": {"enable": True},
        },
    }
    monkeypatch.setattr(model_risk_api, "_identity_governance_section", lambda: section)
    monkeypatch.setattr(
        model_risk_api,
        "_identity_governance_control_status_section",
        lambda: section,
    )
    monkeypatch.delattr(
        app.state,
        "identity_governance_control_runtime",
        raising=False,
    )
    base = "/api/v1/security/assurance/identity-governance/controls"

    assert client.get(f"{base}/status").status_code == 403
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: "user:identity-control-admin",
    )
    original_global_gate = model_risk_api.require_global_permission

    def deny_global_admin(_request, permission):
        assert permission == "admin"
        raise HTTPException(status_code=403, detail="global admin required")

    monkeypatch.setattr(model_risk_api, "require_global_permission", deny_global_admin)
    assert client.get(f"{base}/status").status_code == 403
    monkeypatch.setattr(
        model_risk_api,
        "require_global_permission",
        original_global_gate,
    )
    status = _ok(client.get(f"{base}/status"))
    assert status["enabled"] is True
    assert status["runtime_attached"] is False
    assert status["runtime_attachment_state"] == "unavailable"
    assert status["activation"] == "explicit_startup_injection_required"
    assert status["provider_writes"] is False
    assert status["live_acceptance_verified"] is False

    body = {
        "principal_ref": "prn_" + ("a" * 32),
        "provider_subject_id": "sub_" + ("b" * 32),
        "expected_binding_sha256": "c" * 64,
        "expected_revision": 1,
    }
    assert client.post(f"{base}/federation/entra/observe", json=body).status_code == 503
    assert client.post(
        f"{base}/federation/entra/observe",
        json={**body, "raw_principal": "agent:must-not-be-admitted"},
    ).status_code == 422


def test_identity_control_status_reports_absent_configuration_as_off(monkeypatch):
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: "user:identity-control-admin",
    )
    monkeypatch.delattr(
        app.state,
        "identity_governance_control_runtime",
        raising=False,
    )

    status = _ok(
        client.get(
            "/api/v1/security/assurance/identity-governance/controls/status"
        )
    )
    assert status["enabled"] is False
    assert status["configured"] == {
        "change_coupling": False,
        "federation": False,
        "conditional_access": False,
        "purview_writeback": False,
    }
    assert status["runtime_attached"] is False
    assert status["provider_writes"] is False
    assert status["default_mode"] == "read_only_off"


def test_identity_control_http_composes_exact_runtime_and_separate_purview_actions(
    monkeypatch,
):
    from maverick.ai_identity_governance_controls import (
        CONDITIONAL_ACCESS_SCHEMA,
        FEDERATION_OBSERVATION_SCHEMA,
        AgentPrincipalAuthority,
        AgentPrincipalFederationBinding,
        AgentPrincipalFederationObservation,
        CapabilityRule,
        ConditionalAccessDecisionEngine,
        ConditionalAccessObservation,
        ConditionalAccessObserver,
        EntraAgentPrincipalFederationAdapter,
        IdentityCapabilityMapper,
    )
    from maverick_dashboard import (
        identity_governance_runtime,
        identity_governance_scheduler,
        model_risk_api,
    )

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    tenant_sha256 = identity_governance_scheduler.tenant_binding_sha256(
        require_explicit=True
    )

    def sha(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    principal_ref = "prn_" + sha("agent-principal")[:32]
    provider_subject_id = "sub_" + sha("provider-subject")[:32]
    permission_id = "prm_" + sha("provider-permission")[:32]
    authority = AgentPrincipalAuthority(
        tenant_sha256=tenant_sha256,
        principal_ref=principal_ref,
        authority_binding_sha256=sha("authority-binding"),
        revision=3,
    )
    binding = AgentPrincipalFederationBinding.bind(
        authority,
        provider="entra",
        provider_subject_id=provider_subject_id,
    )

    class FederationTransport:
        def observe(self, request):
            return AgentPrincipalFederationObservation(
                schema=FEDERATION_OBSERVATION_SCHEMA,
                tenant_sha256=request.tenant_sha256,
                provider=request.provider,
                principal_ref=request.principal_ref,
                provider_subject_id=request.provider_subject_id,
                binding_sha256=request.binding_sha256,
                binding_revision=request.binding_revision,
                active=True,
                permission_ids=(permission_id,),
                source_sha256=sha("federation-source"),
                observed_at=1_000.0,
            )

    class ConditionalTransport:
        def observe(self, request):
            return ConditionalAccessObservation(
                schema=CONDITIONAL_ACCESS_SCHEMA,
                tenant_sha256=request.tenant_sha256,
                provider=request.provider,
                principal_ref=request.principal_ref,
                provider_subject_id=request.provider_subject_id,
                binding_sha256=request.binding_sha256,
                binding_revision=request.binding_revision,
                outcome="allow",
                policy_sha256=sha("conditional-policy"),
                reason_codes=("policy_allow",),
                source_sha256=sha("conditional-source"),
                observed_at=1_000.0,
            )

    class MappingRegistry:
        def __init__(self):
            self.values = {}

        def store(self, mapping):
            self.values[
                (
                    mapping.tenant_sha256,
                    mapping.principal_ref,
                    mapping.mapping_sha256,
                )
            ] = mapping
            return True

        def get(self, tenant, principal, mapping_sha256):
            return self.values.get((tenant, principal, mapping_sha256))

    class PurviewService:
        def __init__(self):
            self.calls = []
            self.record = None

        def status(self):
            return {
                "runtime_available": True,
                "provider_writes_possible": True,
                "raw_identity_retained": False,
                "secrets_retained": False,
                "live_acceptance_verified": False,
            }

        def prepare(self, authority_value, mapping, **kwargs):
            self.calls.append(("prepare", kwargs))
            self.record = {
                "id": "IGPW-" + sha("intent")[:32],
                "principal_ref": authority_value.principal_ref,
                "capability_mapping_sha256": mapping.mapping_sha256,
                "asset_id": kwargs["asset_id"],
                "status": "prepared",
                "provider_write_state": "not_attempted",
                "revision": 1,
                "live_acceptance_verified": False,
            }
            return dict(self.record)

        def get_intent(self, intent_id, authority_value, mapping):
            self.calls.append(("get", intent_id))
            assert authority_value.principal_ref == mapping.principal_ref
            return dict(self.record) if self.record and self.record["id"] == intent_id else None

        def execute(self, intent_id, authority_value, mapping, *, expected_revision):
            self.calls.append(("execute", expected_revision))
            assert authority_value.principal_ref == mapping.principal_ref
            assert self.record and self.record["id"] == intent_id
            self.record.update(status="applied", provider_write_state="applied", revision=2)
            return dict(self.record)

        def compensate(self, intent_id, authority_value, mapping, *, expected_revision):
            self.calls.append(("compensate", expected_revision))
            assert authority_value.principal_ref == mapping.principal_ref
            assert self.record and self.record["id"] == intent_id
            self.record.update(
                status="compensated",
                provider_write_state="compensated",
                revision=3,
            )
            return dict(self.record)

    mapper = IdentityCapabilityMapper(
        [
            CapabilityRule(
                tenant_sha256=tenant_sha256,
                provider="entra",
                permission_id=permission_id,
                capabilities=(
                    "agent.execute",
                    "purview.classification.rollback",
                    "purview.classification.write",
                ),
                revision=1,
            )
        ],
        revision=7,
        clock=lambda: 1_000.0,
    )
    purview = PurviewService()

    class DecisionLedger:
        def __init__(self):
            self.records = []

        def record(self, decision, observation, mapping, *, actor):
            assert actor == "user:identity-control-admin"
            result = {
                "decision_record_id": "IGCD-" + sha(decision.decision_sha256)[:32],
                "revision": 1,
                "status": "active",
                "decision_sha256": decision.decision_sha256,
                "mapping_sha256": mapping.mapping_sha256,
                "policy_sha256": observation.policy_sha256,
                "live_acceptance_verified": False,
            }
            self.records.append(result)
            return result

        def get(self, _record_id):
            return None

        def list(self, *, limit=100):
            return self.records[:limit]

        def revoke(self, *_args, **_kwargs):
            return {"status": "revoked"}

        def status(self):
            return {
                "active_decisions": len(self.records),
                "live_acceptance_verified": False,
            }

    decision_ledger = DecisionLedger()
    runtime = identity_governance_runtime.IdentityGovernanceControlRuntime(
        tenant_sha256=tenant_sha256,
        authority_resolver=lambda tenant, principal: (
            authority
            if tenant == tenant_sha256 and principal == authority.principal_ref
            else None
        ),
        federation_binding_resolver=lambda tenant, principal, provider: (
            binding
            if (
                tenant == tenant_sha256
                and principal == authority.principal_ref
                and provider == "entra"
            )
            else None
        ),
        federation_adapters={
            "entra": EntraAgentPrincipalFederationAdapter(FederationTransport()),
        },
        capability_mapper=mapper,
        capability_mapping_registry=MappingRegistry(),
        conditional_access_observers={
            "entra": ConditionalAccessObserver("entra", ConditionalTransport()),
        },
        conditional_access_decision_engine=ConditionalAccessDecisionEngine(
            clock=lambda: 1_000.0
        ),
        conditional_access_decision_ledger=decision_ledger,
        purview_writeback=purview,
    )
    section = {
        "enable": True,
        "entra": {"enable": True},
        "purview": {"enable": True},
        "controls": {
            "enable": True,
            "federation": {"enable": True},
            "conditional_access": {"enable": True},
            "purview_writeback": {"enable": True},
        },
    }
    monkeypatch.setattr(model_risk_api, "_identity_governance_section", lambda: section)
    monkeypatch.setattr(
        model_risk_api,
        "_identity_governance_control_status_section",
        lambda: section,
    )
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: "user:identity-control-admin",
    )
    patch_state(
        monkeypatch,
        app.state,
        "identity_governance_control_runtime",
        runtime,
        raising=False,
    )
    base = "/api/v1/security/assurance/identity-governance/controls"
    binding_body = {
        "principal_ref": principal_ref,
        "provider_subject_id": provider_subject_id,
        "expected_binding_sha256": binding.binding_sha256,
        "expected_revision": authority.revision,
    }

    status = _ok(client.get(f"{base}/status"))
    assert status["runtime_attachment_state"] == "attached"
    assert status["runtime"]["federation_binding_resolver_attached"] is True
    assert status["runtime"]["capability_mapping_registry_attached"] is True
    assert status["provider_writes"] is True
    observed = _ok(client.post(f"{base}/federation/entra/observe", json=binding_body))
    assert observed["principal_ref"] == principal_ref
    mapped = _ok(client.post(f"{base}/capabilities/entra/map", json=binding_body))
    assert mapped["capability_mapping"]["capabilities"] == [
        "agent.execute",
        "purview.classification.rollback",
        "purview.classification.write",
    ]
    decision_body = {
        **binding_body,
        "required_capability": "agent.execute",
        "idempotency_key": "capability-decision-0001",
    }
    capability = _ok(
        client.post(f"{base}/capabilities/entra/decision", json=decision_body)
    )
    assert capability["decision"]["action"] == "permit"
    assert "capability-decision-0001" not in str(capability)
    conditional = _ok(
        client.post(
            f"{base}/conditional-access/entra/decision",
            json=decision_body,
        )
    )
    assert conditional["decision"]["action"] == "permit"
    assert conditional["decision"]["provider_policy_mutated"] is False
    assert conditional["decision_receipt"]["status"] == "active"
    assert len(decision_ledger.records) == 1

    prepare_body = {
        **binding_body,
        "provider": "entra",
        "asset_id": "ast_" + sha("asset")[:32],
        "classification_codes": ["regulated"],
        "expected_asset_binding_sha256": sha("asset-binding"),
        "expected_source_revision": 4,
        "idempotency_key": "purview-prepare-0001",
    }
    prepared = _ok(
        client.post(f"{base}/purview/writebacks/prepare", json=prepare_body),
        201,
    )
    assert prepared["status"] == "prepared"
    assert purview.calls == [
        (
            "prepare",
            {
                "asset_id": prepare_body["asset_id"],
                "classification_codes": ["regulated"],
                "expected_binding_sha256": sha("asset-binding"),
                "expected_source_revision": 4,
                "idempotency_key": "purview-prepare-0001",
            },
        )
    ]
    record_body = {
        "principal_ref": principal_ref,
        "mapping_sha256": prepared["capability_mapping_sha256"],
    }
    loaded = _ok(
        client.post(
            f"{base}/purview/writebacks/{prepared['id']}/get",
            json=record_body,
        )
    )
    assert loaded["status"] == "prepared"
    applied = _ok(
        client.post(
            f"{base}/purview/writebacks/{prepared['id']}/execute",
            json={**record_body, "expected_record_revision": 1},
        )
    )
    assert applied["status"] == "applied"
    compensated = _ok(
        client.post(
            f"{base}/purview/writebacks/{prepared['id']}/compensate",
            json={**record_body, "expected_record_revision": 2},
        )
    )
    assert compensated["status"] == "compensated"
    assert [call[0] for call in purview.calls] == [
        "prepare",
        "get",
        "execute",
        "compensate",
    ]

    stale = client.post(
        f"{base}/federation/entra/observe",
        json={**binding_body, "expected_binding_sha256": "0" * 64},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"] == "federation_binding_stale"

    unregistered_subject = client.post(
        f"{base}/federation/entra/observe",
        json={
            **binding_body,
            "provider_subject_id": "sub_" + sha("unregistered-subject")[:32],
        },
    )
    assert unregistered_subject.status_code == 409
    assert unregistered_subject.json()["detail"] == "provider_subject_not_enrolled"


def test_identity_control_http_rejects_cross_tenant_runtime(monkeypatch):
    from maverick_dashboard import identity_governance_runtime, model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    section = {
        "enable": True,
        "entra": {"enable": True},
        "controls": {"enable": True, "federation": {"enable": True}},
    }
    runtime = identity_governance_runtime.IdentityGovernanceControlRuntime(
        tenant_sha256="f" * 64,
        authority_resolver=lambda _tenant, _principal: None,
        federation_adapters={},
    )
    monkeypatch.setattr(model_risk_api, "_identity_governance_section", lambda: section)
    monkeypatch.setattr(
        model_risk_api,
        "_identity_governance_control_status_section",
        lambda: section,
    )
    monkeypatch.setattr(
        model_risk_api,
        "_human_principal",
        lambda _request: "user:identity-control-admin",
    )
    patch_state(
        monkeypatch,
        app.state,
        "identity_governance_control_runtime",
        runtime,
        raising=False,
    )
    base = "/api/v1/security/assurance/identity-governance/controls"
    status = _ok(client.get(f"{base}/status"))
    assert status["runtime_attached"] is False
    assert status["runtime_attachment_state"] == "tenant_mismatch"
    response = client.post(
        f"{base}/federation/entra/observe",
        json={
            "principal_ref": "prn_" + ("a" * 32),
            "provider_subject_id": "sub_" + ("b" * 32),
            "expected_binding_sha256": "c" * 64,
            "expected_revision": 1,
        },
    )
    assert response.status_code == 409
    assert "tenant binding" in response.json()["detail"]
def test_red_team_schedule_routes_are_admin_and_actor_bound(monkeypatch):
    from maverick import red_team_assurance as rta

    calls: dict = {}
    monkeypatch.setattr(rta, "enabled", lambda: True)
    monkeypatch.setattr(
        rta,
        "list_schedules",
        lambda **_kwargs: {
            "items": [{"id": "RTS-one", "status": "active"}],
            "count": 1,
            "truncated": False,
            "limit": 100,
        },
    )
    monkeypatch.setattr(
        rta,
        "get_schedule",
        lambda schedule_id: (
            {"id": schedule_id, "status": "active"}
            if schedule_id == "RTS-one"
            else None
        ),
    )

    def create(**kwargs):
        calls["create"] = kwargs
        return {"id": "RTS-one", "status": "active", "revision": 1}

    def cancel(schedule_id, **kwargs):
        calls["cancel"] = (schedule_id, kwargs)
        return {"id": schedule_id, "status": "cancelled", "revision": 2}

    def run_due(**kwargs):
        calls["run_due"] = kwargs
        return {
            "campaigns": [],
            "failures": [],
            "count": 0,
            "failure_count": 0,
            "due_count": 0,
            "truncated": False,
            "limit": kwargs["limit"],
        }

    monkeypatch.setattr(rta, "create_schedule", create)
    monkeypatch.setattr(rta, "cancel_schedule", cancel)
    monkeypatch.setattr(rta, "run_due_schedules", run_due)

    body = {
        "asset_id": "MAA-" + ("a" * 32),
        "external_agent_id": "external-one",
        "idempotency_key": "schedule-one",
        "safe_target_environment": True,
        "cadence_seconds": 3600,
    }
    created = _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules",
        json=body,
    ), 201)
    assert created["status"] == "active"
    assert calls["create"]["actor"] == "local:dashboard"
    assert calls["create"]["cadence_seconds"] == 3600
    assert calls["create"]["first_run_at"] is None

    page = _ok(client.get("/api/v1/security/assurance/red-team/schedules"))
    assert page["schedules"][0]["id"] == "RTS-one"
    assert _ok(client.get(
        "/api/v1/security/assurance/red-team/schedules/RTS-one"
    ))["status"] == "active"
    assert client.get(
        "/api/v1/security/assurance/red-team/schedules/RTS-missing"
    ).status_code == 404

    dispatched = _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules/run-due",
        json={"limit": 5},
    ))
    assert dispatched["count"] == 0
    assert calls["run_due"] == {"actor": "local:dashboard", "limit": 5}

    cancelled = _ok(client.post(
        "/api/v1/security/assurance/red-team/schedules/RTS-one/cancel",
        json={"expected_revision": 1, "rationale": "Cadence retired."},
    ))
    assert cancelled["status"] == "cancelled"
    assert calls["cancel"][1]["actor"] == "local:dashboard"

    # Schema floors hold at the boundary: a sub-5-minute cadence never
    # reaches the module.
    too_fast = dict(body, cadence_seconds=60)
    assert client.post(
        "/api/v1/security/assurance/red-team/schedules",
        json=too_fast,
    ).status_code == 422


def test_red_team_schedule_routes_fail_closed_when_disabled():
    assert client.get(
        "/api/v1/security/assurance/red-team/schedules"
    ).status_code == 403
    assert client.post(
        "/api/v1/security/assurance/red-team/schedules/run-due",
        json={},
    ).status_code == 403


def test_policy_pack_change_view_and_reattestation_over_http(monkeypatch):
    from maverick import model_risk_assurance as mra
    from maverick import policy_packs

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(policy_packs, "enabled", lambda: True)
    monkeypatch.setattr(mra, "enabled", lambda: True)

    changes_view = {
        "id": "PPS-one",
        "pack_id": "example-ai-policy",
        "pack_version": "1.0.0",
        "active_pack_version": "1.1.0",
        "needs_refresh": True,
        "refresh_is_forward": True,
        "pending_diff": {"requirements_changed": ["CTRL-1"]},
        "applied_diff": None,
        "requirements": {"CTRL-1": {"status": "current"}},
        "retired_requirements": [],
        "revision": 3,
    }
    monkeypatch.setattr(
        policy_packs,
        "subscription_changes",
        lambda pack_id: changes_view if pack_id == "example-ai-policy" else None,
    )

    calls: dict = {}

    def attest(subscription_id, control_id, **kwargs):
        calls["attest"] = (subscription_id, control_id, kwargs)
        resolved = kwargs["evidence_resolver"]("MRE-one")
        calls["resolved"] = resolved
        return {
            "attestation": {"id": "PPA-one"},
            "subscription": {"id": subscription_id, "revision": 4},
            "idempotent": False,
        }

    monkeypatch.setattr(policy_packs, "attest_control", attest)
    monkeypatch.setattr(
        mra,
        "get_evidence",
        lambda evidence_id: {
            "id": evidence_id,
            "revision": 2,
            "payload_sha256": "b" * 64,
            "evidence_kind": "evaluation",
            "schema": "lightwork.model-risk-evidence.v1",
            "observed_at": 1_700_000_000.0,
            "status": "pending_review",
        },
    )

    view = _ok(client.get(
        "/api/v1/security/assurance/policy-packs/subscriptions/"
        "example-ai-policy/changes"
    ))
    assert view["pending_diff"]["requirements_changed"] == ["CTRL-1"]
    assert client.get(
        "/api/v1/security/assurance/policy-packs/subscriptions/absent/changes"
    ).status_code == 404

    body = {
        "control_id": "CTRL-1",
        "expected_revision": 3,
        "idempotency_key": "attest-ctrl-1-v2",
        "evidence_bindings": [
            {
                "requirement_id": "REQ-1",
                "evidence_id": "MRE-one",
                "evidence_revision": 2,
                "evidence_sha256": "b" * 64,
            }
        ],
    }
    result = _ok(client.post(
        "/api/v1/security/assurance/policy-packs/subscriptions/PPS-one/attest",
        json=body,
    ))
    assert result["attestation"]["id"] == "PPA-one"
    subscription_id, control_id, kwargs = calls["attest"]
    assert (subscription_id, control_id) == ("PPS-one", "CTRL-1")
    assert kwargs["actor"] == "local:dashboard"
    assert kwargs["evidence_bindings"][0]["evidence_sha256"] == "b" * 64
    # The route's resolver adapts assurance rows to the attestation contract:
    # payload digest becomes content digest, the epoch instant becomes ISO.
    assert calls["resolved"]["content_sha256"] == "b" * 64
    assert calls["resolved"]["observed_at"].endswith("+00:00")
    assert calls["resolved"]["evidence_kind"] == "evaluation"

    # A malformed digest never reaches the module.
    bad = dict(body)
    bad["evidence_bindings"] = [dict(body["evidence_bindings"][0], evidence_sha256="XYZ")]
    assert client.post(
        "/api/v1/security/assurance/policy-packs/subscriptions/PPS-one/attest",
        json=bad,
    ).status_code == 422


def test_policy_pack_change_and_attest_routes_require_a_tenant(monkeypatch):
    from maverick import policy_packs

    monkeypatch.setattr(policy_packs, "enabled", lambda: True)
    assert client.get(
        "/api/v1/security/assurance/policy-packs/subscriptions/any/changes"
    ).status_code == 409
