"""The needs-attention digest: fail-soft per section, exact counts when seeded.

The digest is read-side aggregation with no knob of its own; a disabled
source module must yield ``enabled: false`` and count nothing, and a seeded
overdue clock / literacy gap / outdated FRIA / flagged route must each count.
"""
from __future__ import annotations

import hashlib
import time

import pytest
from maverick import config, governance_alerts


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _enable_all(tmp_path):
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\nenable = true\n\n"
        "[model_risk_assurance]\nenable = true\ngate_promotions = false\n\n"
        "[ai_incident_reporting]\nenable = true\n\n"
        "[ai_literacy]\nenable = true\n\n"
        "[eu_conformity]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()


def test_everything_disabled_yields_a_quiet_digest():
    report = governance_alerts.digest()
    assert report["attention_count"] == 0
    for section in report["sections"].values():
        assert section["enabled"] is False


def test_parameter_validation():
    with pytest.raises(ValueError, match="due_soon_seconds"):
        governance_alerts.digest(due_soon_seconds=0)
    with pytest.raises(ValueError, match="expiring_days"):
        governance_alerts.digest(expiring_days=0)
    with pytest.raises(ValueError, match="now"):
        governance_alerts.digest(now=True)


def test_seeded_registers_are_counted(tmp_path):
    _enable_all(tmp_path)
    from maverick import ai_incident_reporting as air
    from maverick import ai_literacy
    from maverick import eu_conformity as euc
    from maverick import model_risk_assurance as mra

    now = time.time()

    officer = mra.ModelRiskAssuranceOfficer()
    observation = officer.observe_asset(
        asset_type="model",
        source="alerts_test",
        source_id="triage-model",
        display_name="Triage model",
        version_digest=hashlib.sha256(b"triage-v1").hexdigest(),
        actor="inventory-operator",
        observed_at=now,
        metadata={},
        dependencies=[],
    )
    incident = officer.record_incident(
        observation["asset_id"],
        source_id="incident-1",
        severity="high",
        summary="The triage model misrouted an emergency case.",
        actor="incident-manager",
        occurred_at=now - 30 * 86_400,
        evidence_ids=[],
    )
    # A 2-day clock declared 20 days after awareness began: overdue.
    air.declare_serious_incident(
        incident["id"],
        category="critical_infrastructure_disruption",
        became_aware_at=now - 20 * 86_400,
        causal_link="under_investigation",
        member_state="DE",
        authority="Bundesnetzagentur market surveillance",
        declared_by="incident-manager",
    )

    ai_literacy.set_role_requirement(
        "operator",
        [{"key": "ai-fundamentals", "title": "AI fundamentals",
          "validity_days": None}],
        actor="hr-lead",
    )
    ai_literacy.assign_roles("analyst", ["operator"], actor="hr-lead")

    asset = "MAA-" + "a" * 32
    record = euc.open_fria(asset, context="triage", actor="dpo")
    revision = record["revision"]
    for element in euc.FRIA_ELEMENTS:
        record = euc.assert_fria_element(
            record["id"], element, content="Assessed.", actor="dpo",
            expected_revision=revision,
        )
        revision = record["revision"]
    completed = euc.complete_fria(
        record["id"], assessor="dpo", expected_revision=revision,
    )
    euc.mark_fria_outdated(
        completed["id"], reason="New market.", actor="dpo",
        expected_revision=completed["revision"],
    )
    route = euc.record_assessment_route(
        asset, route="internal_control_annex_vi", annex_iii_point=4,
        harmonised_standards_applied=True, common_specifications_applied=False,
        rationale="Point 4 internal control.", actor="quality-lead",
    )
    euc.mark_substantial_modification(
        asset, reason="New population.", actor="quality-lead",
        expected_revision=route["revision"],
    )

    report = governance_alerts.digest(now=now)
    sections = report["sections"]
    assert len(sections["serious_incidents"]["overdue"]) == 1
    assert sections["serious_incidents"]["due_soon"] == []
    assert sections["ai_literacy"]["missing"] == 1
    assert sections["ai_literacy"]["expired"] == 0
    assert sections["ai_literacy"]["unreconciled_ai_literacy_data"] is True
    assert len(sections["eu_conformity"]["outdated_frias"]) == 1
    assert sections["eu_conformity"]["reassessment_required"] == [asset]
    assert report["attention_count"] == 5


def test_expiring_soon_counts_within_the_horizon(tmp_path):
    _enable_all(tmp_path)
    from maverick import ai_literacy

    now = time.time()
    ai_literacy.set_role_requirement(
        "operator",
        [{"key": "refresher", "title": "Annual refresher", "validity_days": 365}],
        actor="hr-lead",
    )
    ai_literacy.assign_roles("analyst", ["operator"], actor="hr-lead")
    # Completed ~350 days ago: still current, expiring within 30 days.
    ai_literacy.record_completion(
        "analyst", "refresher",
        completed_at=now - 350 * 86_400,
        evidence_ref="lms:course/attempt-1",
        actor="hr-lead",
    )
    report = governance_alerts.digest(now=now)
    literacy = report["sections"]["ai_literacy"]
    assert literacy["missing"] == 0
    assert literacy["expired"] == 0
    assert literacy["expiring_soon"] == 1
    assert literacy["unreconciled_ai_literacy_data"] is True
    assert report["attention_count"] == 2
