"""Governed portfolio-risk hierarchy, scoring, and snapshot tests."""
from __future__ import annotations

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from maverick import model_risk_assurance as mra
from maverick import portfolio_risk
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _write_config(tmp_path, *, portfolio: bool = True) -> None:
    section = "\n[portfolio_risk]\nenable = true\n" if portfolio else ""
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\n"
        "enable = true\n"
        "\n[model_risk_assurance]\n"
        "enable = true\n"
        "gate_promotions = false\n"
        f"{section}",
        encoding="utf-8",
    )


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    _write_config(tmp_path)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _observe(
    officer: mra.ModelRiskAssuranceOfficer,
    label: str,
    *,
    asset_type: str,
) -> dict:
    return officer.observe_asset(
        asset_type=asset_type,
        source="portfolio_test",
        source_id=label,
        display_name=label.replace("-", " ").title(),
        version_digest=_hex(f"artifact:{label}"),
        actor="inventory-operator",
        observed_at=officer._now(),  # noqa: SLF001 - fixed authority test clock
        metadata={},
        dependencies=[],
    )


def _declaration(
    officer: mra.ModelRiskAssuranceOfficer,
    observation: dict,
    *,
    parent_asset_id: str | None = None,
    prohibited_signal: bool = False,
    review: bool = True,
) -> dict:
    now = officer._now()  # noqa: SLF001 - fixed authority test clock
    proposed = officer.declare_asset(
        observation["asset_id"],
        owner="AI Risk Committee",
        purpose="Governed portfolio component.",
        intended_use="Human-supervised decision support.",
        actor="model-owner",
        risk_tier="high" if prohibited_signal else "medium",
        risk_context={
            "human_oversight": True,
            "prohibited_signals": ["social_scoring"] if prohibited_signal else [],
        },
        eu_ai_act={
            "category": "not_applicable",
            "asserted_by": "qualified-reviewer",
            "asserted_at": now,
            "as_of": "2026-08-23",
            "source_ref": mra.EU_AI_ACT_METADATA["source"],
            "rationale": "Reviewed deployment context is outside asserted scope.",
        },
        parent_asset_id=parent_asset_id,
    )
    if not review:
        return proposed
    return officer.review_declaration(
        observation["asset_id"],
        decision="approved",
        rationale="Hierarchy, ownership, use, and applicability were reviewed.",
        reviewer="independent-risk-reviewer",
        expected_revision=proposed["revision"],
    )


def test_feature_gate_is_explicit_and_default_off(_isolate):
    from maverick import config

    assert portfolio_risk.enabled() is True
    _write_config(_isolate, portfolio=False)
    config.reset_config_cache()
    assert portfolio_risk.enabled() is False
    with pytest.raises(portfolio_risk.PortfolioRiskConfigError):
        portfolio_risk.PortfolioRiskService().current_report()


def test_hierarchy_validates_types_cycles_tenant_and_review_invalidation():
    officer = mra.ModelRiskAssuranceOfficer()
    with tenant_scope(tenant="alpha"):
        system = _observe(officer, "system", asset_type="system")
        component_a = _observe(officer, "component-a", asset_type="component")
        component_b = _observe(officer, "component-b", asset_type="component")
        agent = _observe(officer, "agent", asset_type="agent")
        system_declaration = _declaration(officer, system)
        component_a_declaration = _declaration(
            officer,
            component_a,
            parent_asset_id=system["asset_id"],
        )
        _declaration(
            officer,
            component_b,
            parent_asset_id=component_a["asset_id"],
        )
        agent_declaration = _declaration(
            officer,
            agent,
            parent_asset_id=component_b["asset_id"],
        )

        assert officer.hierarchy_binding(agent["asset_id"])["parent_asset_id"] == (
            component_b["asset_id"]
        )
        assert len(officer.hierarchy_binding(agent["asset_id"])["ancestors"]) == 3

        with pytest.raises(ValueError, match="cycle"):
            officer.update_declaration(
                component_a["asset_id"],
                parent_asset_id=component_b["asset_id"],
                expected_revision=component_a_declaration["revision"],
                actor="model-owner",
            )
        with pytest.raises(ValueError, match="cannot be governed"):
            officer.update_declaration(
                component_a["asset_id"],
                parent_asset_id=agent["asset_id"],
                expected_revision=component_a_declaration["revision"],
                actor="model-owner",
            )
        with pytest.raises(ValueError, match="system assets cannot have a parent"):
            officer.update_declaration(
                system["asset_id"],
                parent_asset_id=component_a["asset_id"],
                expected_revision=system_declaration["revision"],
                actor="model-owner",
            )

        moved = officer.update_declaration(
            agent["asset_id"],
            parent_asset_id=component_a["asset_id"],
            expected_revision=agent_declaration["revision"],
            actor="model-owner",
        )
        assert moved["parent_asset_id"] == component_a["asset_id"]
        assert moved["review"] is None
        assert moved["lifecycle"] == "proposed"

    with tenant_scope(tenant="beta"):
        beta_agent = _observe(officer, "beta-agent", asset_type="agent")
        with pytest.raises(mra.ModelRiskStateError, match="active tenant"):
            _declaration(
                officer,
                beta_agent,
                parent_asset_id=system["asset_id"],
            )


def test_ancestor_revision_change_makes_descendant_review_stale():
    officer = mra.ModelRiskAssuranceOfficer()
    system = _observe(officer, "system", asset_type="system")
    component = _observe(officer, "component", asset_type="component")
    system_declaration = _declaration(officer, system)
    _declaration(officer, component, parent_asset_id=system["asset_id"])

    officer.update_declaration(
        system["asset_id"],
        purpose="Changed governed system purpose.",
        expected_revision=system_declaration["revision"],
        actor="system-owner",
    )
    stale_assets = {
        row["asset_id"]
        for row in officer.findings()
        if row["finding_type"] == "stale_declaration_authority"
    }
    assert component["asset_id"] in stale_assets


def test_hierarchy_depth_is_bounded():
    officer = mra.ModelRiskAssuranceOfficer()
    system = _observe(officer, "depth-system", asset_type="system")
    _declaration(officer, system, review=False)
    parent = system
    for index in range(16):
        component = _observe(
            officer,
            f"depth-component-{index}",
            asset_type="component",
        )
        _declaration(
            officer,
            component,
            parent_asset_id=parent["asset_id"],
            review=False,
        )
        parent = component
    too_deep = _observe(officer, "depth-component-overflow", asset_type="component")
    with pytest.raises(ValueError, match="16-level limit"):
        _declaration(
            officer,
            too_deep,
            parent_asset_id=parent["asset_id"],
            review=False,
        )


def test_formula_v1_rolls_up_children_and_traces_findings_incidents_acceptances():
    now = time.time()
    officer = mra.ModelRiskAssuranceOfficer(clock=lambda: now)
    system = _observe(officer, "system", asset_type="system")
    component = _observe(officer, "component", asset_type="component")
    agent = _observe(officer, "agent", asset_type="agent")
    _declaration(officer, system)
    _declaration(officer, component, parent_asset_id=system["asset_id"])
    _declaration(
        officer,
        agent,
        parent_asset_id=component["asset_id"],
        prohibited_signal=True,
    )
    incident = officer.record_incident(
        component["asset_id"],
        source_id="incident-1",
        severity="medium",
        summary="A current assurance incident requires investigation.",
        actor="incident-manager",
        occurred_at=now,
        evidence_ids=[],
    )
    accepted_finding = next(
        row
        for row in officer.findings(now=now)
        if row["asset_id"] == system["asset_id"]
        and row["finding_type"] == "evaluation_evidence_missing"
    )
    acceptance = officer.accept_risk(
        accepted_finding["id"],
        finding_sha256=accepted_finding["finding_sha256"],
        rationale="Bounded temporary acceptance while evidence is refreshed.",
        reviewer="risk-committee-chair",
        expires_at=now + 3600,
    )
    service = portfolio_risk.PortfolioRiskService(officer=officer, clock=lambda: now)
    report = service.current_report()

    assert report["formula_version"] == portfolio_risk.FORMULA_VERSION
    assert report["portfolio_inherent_score"] == 100
    assert report["portfolio_score"] == 100
    assert report["risk_load"] <= report["inherent_risk_load"]
    assert report["legal_certification"] is False
    assert report["compliance_verdict"] == "not_provided"
    nodes = {row["asset_id"]: row for row in report["assets"]}
    assert nodes[agent["asset_id"]]["direct_residual_score"] == 100
    assert nodes[component["asset_id"]]["residual_score"] == 100
    assert nodes[system["asset_id"]]["residual_score"] == 100

    accepted = next(
        row for row in report["contributors"] if row["finding_id"] == accepted_finding["id"]
    )
    assert accepted["accepted"] is True
    assert accepted["residual_points"] == 0
    assert accepted["acceptance"]["record_id"] == acceptance["id"]
    assert accepted["acceptance"]["finding_sha256"] == accepted_finding["finding_sha256"]
    assert accepted["acceptance"]["record_sha256"]

    incident_contributor = next(
        row
        for row in report["contributors"]
        if any(
            citation["record_id"] == incident["id"]
            for citation in row["source_citations"]
        )
    )
    incident_citation = next(
        citation
        for citation in incident_contributor["source_citations"]
        if citation["record_id"] == incident["id"]
    )
    assert incident_citation["revision"] == incident["revision"]
    assert incident_citation["record_sha256"]

    expired = service.current_report(now=now + 3601)
    expired_contributor = next(
        row
        for row in expired["contributors"]
        if row["finding_id"] == accepted_finding["id"]
    )
    assert expired_contributor["accepted"] is False
    assert expired_contributor["residual_points"] == 75

    critical = next(row for row in officer.findings(now=now) if row["severity"] == "critical")
    with pytest.raises(ValueError, match="critical findings cannot"):
        officer.accept_risk(
            critical["id"],
            finding_sha256=critical["finding_sha256"],
            rationale="This must never suppress critical risk.",
            reviewer="risk-committee-chair",
            expires_at=now + 3600,
        )


def test_quarter_snapshots_are_cas_governed_superseded_and_closed():
    clock = [datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()]
    officer = mra.ModelRiskAssuranceOfficer(clock=lambda: clock[0])
    _observe(officer, "model", asset_type="model")
    service = portfolio_risk.PortfolioRiskService(
        officer=officer,
        clock=lambda: clock[0],
    )

    created = service.refresh_current_snapshot(actor="risk-officer")
    assert created["period_id"] == "2026-Q3"
    assert created["revision"] == 1
    assert created["period_status"] == "current"
    assert created["supersessions"] == []

    idempotent = service.refresh_current_snapshot(
        actor="risk-officer",
        expected_revision=created["revision"],
    )
    assert idempotent["revision"] == created["revision"]
    clock[0] += 1
    refreshed = service.refresh_current_snapshot(
        actor="risk-officer",
        expected_revision=created["revision"],
    )
    assert refreshed["revision"] == 2
    assert refreshed["supersessions"] == [{
        **refreshed["supersessions"][0],
        "record_revision": 1,
        "report_sha256": created["report_sha256"],
        "source_state_sha256": created["source_state_sha256"],
    }]
    with pytest.raises(RecordConflict):
        service.refresh_current_snapshot(
            actor="stale-writer",
            expected_revision=created["revision"],
        )

    clock[0] = datetime(2026, 10, 1, 0, tzinfo=timezone.utc).timestamp()
    closed = service.get_snapshot("2026-Q3")
    assert closed is not None
    assert closed["period_status"] == "closed"
    with pytest.raises(portfolio_risk.ClosedPortfolioPeriod):
        service.refresh_current_snapshot(
            actor="risk-officer",
            expected_revision=refreshed["revision"],
            period_id="2026-Q3",
        )


def test_snapshot_cas_has_one_winner_and_tenant_storage_isolated():
    officer = mra.ModelRiskAssuranceOfficer()
    with tenant_scope(tenant="alpha"):
        _observe(officer, "alpha-model", asset_type="model")
        service = portfolio_risk.PortfolioRiskService(officer=officer)
        first = service.refresh_current_snapshot(actor="initial-publisher")

    def refresh(actor: str) -> str:
        with tenant_scope(tenant="alpha"):
            contender = portfolio_risk.PortfolioRiskService(
                officer=mra.ModelRiskAssuranceOfficer()
            )
            try:
                contender.refresh_current_snapshot(
                    actor=actor,
                    expected_revision=first["revision"],
                )
            except RecordConflict:
                return "conflict"
            return "published"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(refresh, ("writer-one", "writer-two")))
    assert sorted(outcomes) == ["conflict", "published"]

    with tenant_scope(tenant="alpha"):
        assert len(portfolio_risk.PortfolioRiskService().list_snapshots()) == 1
    with tenant_scope(tenant="beta"):
        assert portfolio_risk.PortfolioRiskService().list_snapshots() == []


def _governed_quarter(clock):
    """One system->component->agent hierarchy under a fixed test clock."""
    officer = mra.ModelRiskAssuranceOfficer(clock=lambda: clock[0])
    system = _observe(officer, "system", asset_type="system")
    component = _observe(officer, "component", asset_type="component")
    agent = _observe(officer, "agent", asset_type="agent")
    _declaration(officer, system)
    _declaration(officer, component, parent_asset_id=system["asset_id"])
    _declaration(
        officer,
        agent,
        parent_asset_id=component["asset_id"],
        prohibited_signal=True,
    )
    service = portfolio_risk.PortfolioRiskService(
        officer=officer, clock=lambda: clock[0]
    )
    return officer, service, component


def test_trend_with_no_prior_quarter_reports_no_comparison():
    clock = [datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()]
    _officer, service, _component = _governed_quarter(clock)
    service.refresh_current_snapshot(actor="risk-officer")

    trend = service.portfolio_trend()
    assert trend["schema"] == portfolio_risk.TREND_SCHEMA
    assert trend["current_period_id"] == "2026-Q3"
    assert trend["expected_prior_period_id"] == "2026-Q2"
    assert trend["comparison_available"] is False
    assert trend["prior_period_id"] is None
    assert trend["direction"] == "not_available"
    assert trend["portfolio_score"]["delta"] is None
    assert trend["risk_load"]["delta"] is None
    assert trend["contributor_deltas"] == []
    assert trend["legal_certification"] is False
    assert trend["notice"] == mra.NON_CERTIFICATION_NOTICE
    assert len(trend["trend_sha256"]) == 64


def test_trend_compares_consecutive_quarters_and_directions_on_risk_load():
    clock = [datetime(2026, 5, 15, 12, tzinfo=timezone.utc).timestamp()]
    officer, service, component = _governed_quarter(clock)
    prior = service.refresh_current_snapshot(actor="risk-officer")
    assert prior["period_id"] == "2026-Q2"

    clock[0] = datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()
    officer.record_incident(
        component["asset_id"],
        source_id="q3-incident",
        severity="medium",
        summary="A new current-quarter incident increases the risk load.",
        actor="incident-manager",
        occurred_at=clock[0],
        evidence_ids=[],
    )
    service.refresh_current_snapshot(actor="risk-officer")

    trend = service.portfolio_trend()
    assert trend["comparison_available"] is True
    assert trend["prior_period_id"] == "2026-Q2"
    assert trend["is_consecutive"] is True
    # The prohibited-signal agent pins the max-based score at 100 in both
    # quarters, so the direction must come from the risk-load fallback -- the
    # exact branch the pre-handoff Ruff finding (FURB110) lived on.
    assert trend["portfolio_score"]["delta"] == 0
    assert trend["risk_load"]["delta"] > 0
    assert trend["direction_basis"] == "risk_load"
    assert trend["direction"] == "worsened"

    new_contributors = [
        row for row in trend["contributor_deltas"] if row["prior_present"] is False
    ]
    # The incident lands as a derived assurance finding contributor carrying
    # the medium-severity points -- the exact 50-point load increase above.
    assert [row["delta"] for row in new_contributors] == [50]
    assert new_contributors[0]["source_kind"] == "finding"
    assert new_contributors[0]["current_residual_points"] == 50
    assert trend["contributor_delta_count"] >= len(trend["contributor_deltas"])
    assert trend["drill_through_ids"]["contributor_ids"]
    for row in trend["contributor_deltas"]:
        assert row["direction"] in {"worsened", "improved", "unchanged"}


def test_trend_after_skipped_quarter_is_not_consecutive():
    clock = [datetime(2026, 2, 15, 12, tzinfo=timezone.utc).timestamp()]
    _officer, service, _component = _governed_quarter(clock)
    first = service.refresh_current_snapshot(actor="risk-officer")
    assert first["period_id"] == "2026-Q1"

    clock[0] = datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()
    service.refresh_current_snapshot(actor="risk-officer")

    trend = service.portfolio_trend()
    assert trend["comparison_available"] is True
    assert trend["prior_period_id"] == "2026-Q1"
    assert trend["expected_prior_period_id"] == "2026-Q2"
    assert trend["is_consecutive"] is False


def test_trend_requires_current_snapshot_and_validates_limit():
    clock = [datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()]
    _officer, service, _component = _governed_quarter(clock)
    with pytest.raises(portfolio_risk.PortfolioRiskStateError, match="missing"):
        service.portfolio_trend()

    service.refresh_current_snapshot(actor="risk-officer")
    for bad in (0, -1, 501, True, "10"):
        with pytest.raises(ValueError, match="contributor_limit"):
            service.portfolio_trend(contributor_limit=bad)


def test_contributor_drillthrough_is_bounded_and_content_free():
    clock = [datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()]
    _officer, service, _component = _governed_quarter(clock)
    snapshot = service.refresh_current_snapshot(actor="risk-officer")
    contributor_id = snapshot["report"]["contributors"][0]["contributor_id"]

    row = service.get_contributor_drillthrough("2026-Q3", contributor_id)
    assert row is not None
    assert row["contributor_id"] == contributor_id
    assert row["period_id"] == "2026-Q3"
    assert row["report_sha256"] == snapshot["report_sha256"]
    assert row["legal_certification"] is False
    # Identity projection only: never summaries, citations, or acceptance text.
    assert set(row) == {
        "snapshot_id", "snapshot_revision", "period_id", "report_sha256",
        "source_state_sha256", "contributor_id", "finding_id", "asset_id",
        "source_kind", "finding_type", "severity", "inherent_points",
        "residual_points", "accepted", "legal_certification",
        "compliance_verdict",
    }

    assert service.get_contributor_drillthrough("2027-Q1", contributor_id) is None
    assert service.get_contributor_drillthrough("2026-Q3", "absent-id") is None
    with pytest.raises(ValueError, match="contributor_id"):
        service.get_contributor_drillthrough("2026-Q3", "../escape")
    with pytest.raises(ValueError, match="period_id"):
        service.get_contributor_drillthrough("2026-Q9", contributor_id)


def _projection_row(**overrides):
    row = {
        "contributor_id": "MAF-abc123",
        "source_kind": "finding",
        "finding_id": "MAF-abc123",
        "finding_sha256": "a" * 64,
        "finding_type": "evaluation_evidence_missing",
        "asset_id": "MAA-def456",
        "severity": "high",
        "summary": "bounded",
        "accepted": False,
        "acceptance": None,
        "inherent_points": 75,
        "residual_points": 75,
        "source_citations": [],
    }
    row.update(overrides)
    return row


def _projection_snapshot(rows):
    return {"report": {"contributors": rows, "counts": {"contributors": len(rows)}}}


def test_trend_contributor_projection_refuses_corruption():
    parse = portfolio_risk.PortfolioRiskService._trend_contributors
    assert "MAF-abc123" in parse(_projection_snapshot([_projection_row()]))

    corrupt = [
        # Count no longer matches the projection list.
        {"report": {"contributors": [_projection_row()], "counts": {"contributors": 2}}},
        # A field was added or removed from the closed projection shape.
        _projection_snapshot([{**_projection_row(), "extra": True}]),
        # Severity/points tampering.
        _projection_snapshot([_projection_row(severity="catastrophic")]),
        _projection_snapshot([_projection_row(inherent_points=74)]),
        _projection_snapshot([_projection_row(residual_points=40)]),
        # Acceptance invariants: only non-critical findings zero out.
        _projection_snapshot([_projection_row(accepted=True)]),
        _projection_snapshot([
            _projection_row(
                accepted=True, residual_points=0, severity="critical",
                inherent_points=100,
            ),
        ]),
        # Incident rows must not carry finding drill-through identity.
        _projection_snapshot([
            _projection_row(source_kind="incident"),
        ]),
        # Duplicated identity.
        _projection_snapshot([_projection_row(), _projection_row()]),
        # Unsafe drill-through identifier.
        _projection_snapshot([_projection_row(contributor_id="../escape")]),
    ]
    for snapshot in corrupt:
        with pytest.raises(portfolio_risk.PortfolioRiskStateError):
            parse(snapshot)


def test_trend_and_drillthrough_are_tenant_isolated():
    clock = [datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()]
    with tenant_scope(tenant="acme"):
        _officer, service, _component = _governed_quarter(clock)
        snapshot = service.refresh_current_snapshot(actor="risk-officer")
        contributor_id = snapshot["report"]["contributors"][0]["contributor_id"]
        assert service.portfolio_trend()["current_period_id"] == "2026-Q3"

    with tenant_scope(tenant="globex"):
        other = portfolio_risk.PortfolioRiskService(
            officer=mra.ModelRiskAssuranceOfficer(clock=lambda: clock[0]),
            clock=lambda: clock[0],
        )
        with pytest.raises(portfolio_risk.PortfolioRiskStateError, match="missing"):
            other.portfolio_trend()
        assert other.get_contributor_drillthrough("2026-Q3", contributor_id) is None


# Retained broader end-to-end trend scenarios from the feature branch.
def test_portfolio_trend_handles_first_quarter_and_consecutive_drillthrough():
    clock = [datetime(2026, 6, 30, 12, tzinfo=timezone.utc).timestamp()]
    officer = mra.ModelRiskAssuranceOfficer(clock=lambda: clock[0])
    service = portfolio_risk.PortfolioRiskService(
        officer=officer,
        clock=lambda: clock[0],
    )

    with tenant_scope(tenant="alpha"):
        first_asset = _observe(officer, "q2-model", asset_type="model")
        first = service.refresh_current_snapshot(actor="risk-officer")
        first_trend = service.portfolio_trend(contributor_limit=10)

        assert first["period_id"] == "2026-Q2"
        assert first_trend["comparison_available"] is False
        assert first_trend["expected_prior_period_id"] == "2026-Q1"
        assert first_trend["direction"] == "not_available"

        clock[0] = datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()
        second_asset = _observe(officer, "q3-model", asset_type="model")
        second = service.refresh_current_snapshot(actor="risk-officer")
        trend = service.portfolio_trend(contributor_limit=10)

        assert second["period_id"] == "2026-Q3"
        assert trend["comparison_available"] is True
        assert trend["prior_period_id"] == "2026-Q2"
        assert trend["expected_prior_period_id"] == "2026-Q2"
        assert trend["is_consecutive"] is True
        assert trend["trend_sha256"]
        assert trend["contributor_delta_count"] >= 1

        current_refs = [
            row for row in trend["contributor_deltas"] if row["current_present"]
        ]
        assert current_refs
        selected = current_refs[0]
        detail = service.get_contributor_drillthrough(
            "2026-Q3",
            selected["contributor_id"],
        )
        assert detail is not None
        assert detail["period_id"] == "2026-Q3"
        assert detail["contributor_id"] == selected["contributor_id"]
        assert detail["asset_id"] in {first_asset["asset_id"], second_asset["asset_id"]}
        assert "description" not in detail
        assert "rationale" not in detail


def test_portfolio_trend_reports_skipped_quarter_and_preserves_tenant_boundary():
    clock = [datetime(2026, 3, 31, 12, tzinfo=timezone.utc).timestamp()]
    officer = mra.ModelRiskAssuranceOfficer(clock=lambda: clock[0])
    service = portfolio_risk.PortfolioRiskService(
        officer=officer,
        clock=lambda: clock[0],
    )

    with tenant_scope(tenant="alpha"):
        _observe(officer, "q1-model", asset_type="model")
        service.refresh_current_snapshot(actor="risk-officer")
        clock[0] = datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()
        service.refresh_current_snapshot(actor="risk-officer")
        trend = service.portfolio_trend()
        assert trend["prior_period_id"] == "2026-Q1"
        assert trend["expected_prior_period_id"] == "2026-Q2"
        assert trend["is_consecutive"] is False

    with tenant_scope(tenant="beta"):
        _observe(officer, "beta-model", asset_type="model")
        service.refresh_current_snapshot(actor="risk-officer")
        isolated = service.portfolio_trend()
        assert isolated["comparison_available"] is False
        assert isolated["prior_period_id"] is None


def test_portfolio_trend_rejects_corrupted_contributor_projection():
    clock = [datetime(2026, 6, 30, 12, tzinfo=timezone.utc).timestamp()]
    officer = mra.ModelRiskAssuranceOfficer(clock=lambda: clock[0])
    service = portfolio_risk.PortfolioRiskService(
        officer=officer,
        clock=lambda: clock[0],
    )
    with tenant_scope(tenant="alpha"):
        _observe(officer, "model", asset_type="model")
        service.refresh_current_snapshot(actor="risk-officer")
        clock[0] = datetime(2026, 8, 23, 12, tzinfo=timezone.utc).timestamp()
        current = service.refresh_current_snapshot(actor="risk-officer")

        def corrupt(row):
            row["report"]["counts"]["contributors"] += 1

        service._snapshots.update(  # noqa: SLF001 - persisted corruption test
            current["id"],
            corrupt,
            expected_revision=current["revision"],
            action="test_corruption",
            actor="test",
        )
        with pytest.raises(portfolio_risk.PortfolioRiskStateError):
            service.portfolio_trend()
