"""EU AI Act Art. 73 serious-incident clocks, lifecycle, and report drafts.

The assertions that matter: the windows are the AI Act's tiered 2/10/15 DAYS
from awareness — never the GDPR Art. 33 72-hour clock — every consequential
step is a named human assertion, and terminal states accept nothing further.
"""
from __future__ import annotations

import hashlib
import time

import pytest
from maverick import ai_incident_reporting as air
from maverick import config
from maverick import model_risk_assurance as mra
from maverick.privacy_ops import RecordConflict

_DAY = 86_400


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\n"
        "enable = true\n"
        "\n[model_risk_assurance]\n"
        "enable = true\n"
        "gate_promotions = false\n"
        "\n[ai_incident_reporting]\n"
        "enable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _incident(*, severity: str = "high", occurred_at: float | None = None) -> dict:
    officer = mra.ModelRiskAssuranceOfficer()
    now = time.time()
    observation = officer.observe_asset(
        asset_type="model",
        source="incident_test",
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
        source_id="incident-1",
        severity=severity,
        summary="The triage model misrouted an emergency case.",
        actor="incident-manager",
        occurred_at=occurred_at if occurred_at is not None else now,
        evidence_ids=[],
    )


def _declare(incident, **overrides):
    aware = overrides.pop("became_aware_at", incident["occurred_at"] + 3_600)
    kwargs = {
        "category": "serious_health_harm",
        "widespread": False,
        "became_aware_at": aware,
        "causal_link": "reasonably_likely",
        "member_state": "DE",
        "authority": "Bundesnetzagentur market surveillance",
        "declared_by": "incident-manager",
        **overrides,
    }
    return air.declare_serious_incident(incident["id"], **kwargs)


# ---- the clocks are the AI Act's, not the GDPR's ---------------------------


def test_deadline_tiers_follow_article_73_not_article_33():
    default = air.classify_deadline("serious_health_harm")
    assert default["window_days"] == 15
    assert default["window_seconds"] == 15 * _DAY
    assert default["deadline_citation"] == "Art. 73(2)"

    death = air.classify_deadline("death")
    assert death["window_days"] == 10
    assert death["deadline_citation"] == "Art. 73(4)"
    assert death["category_citation"] == "Art. 3(49)(a)"

    infrastructure = air.classify_deadline("critical_infrastructure_disruption")
    assert infrastructure["window_days"] == 2
    assert infrastructure["deadline_citation"] == "Art. 73(3)"
    assert infrastructure["category_citation"] == "Art. 3(49)(b)"

    # Art. 3(61) widespread infringement forces the 2-day clock, and the
    # strictest applicable window always binds (death + widespread -> 2).
    widespread = air.classify_deadline("fundamental_rights_infringement", widespread=True)
    assert widespread["window_days"] == 2
    assert widespread["deadline_citation"] == "Art. 73(3)"
    assert air.classify_deadline("death", widespread=True)["window_days"] == 2
    # Widespread never LOOSENS a stricter clock.
    assert air.classify_deadline(
        "critical_infrastructure_disruption", widespread=True
    )["window_days"] == 2

    # None of the tiers is the GDPR 72-hour breach clock.
    for token in air.SERIOUS_INCIDENT_CATEGORIES:
        assert air.classify_deadline(token)["window_seconds"] != 72 * 3_600

    with pytest.raises(ValueError, match="category"):
        air.classify_deadline("data_breach")
    with pytest.raises(ValueError, match="widespread"):
        air.classify_deadline("death", widespread="yes")


def test_declaration_starts_the_clock_from_awareness():
    incident = _incident()
    aware = incident["occurred_at"] + 3_600
    record = _declare(incident, category="death", became_aware_at=aware)

    assert record["status"] == "declared"
    assert record["report_due_at"] == pytest.approx(aware + 10 * _DAY)
    assert record["deadline_citation"] == "Art. 73(4)"
    assert record["member_state"] == "DE"
    assert record["incident_id"] == incident["id"]
    assert record["legal_certification"] is False
    assert record["regulation"]["consolidated"] == "2026-07-27"

    clock = air.report_clock(record, now=aware + _DAY)
    assert clock["overdue"] is False
    assert clock["seconds_remaining"] == pytest.approx(9 * _DAY)
    late = air.report_clock(record, now=aware + 11 * _DAY)
    assert late["overdue"] is True
    assert late["seconds_remaining"] == 0.0


def test_declaration_refuses_bad_inputs_and_duplicates():
    incident = _incident()
    with pytest.raises(KeyError, match="not recorded"):
        air.declare_serious_incident(
            "MRI-missing",
            category="death",
            became_aware_at=time.time(),
            causal_link="established",
            member_state="DE",
            authority="authority",
            declared_by="operator",
        )
    with pytest.raises(ValueError, match="causal_link"):
        _declare(incident, causal_link="maybe")
    with pytest.raises(ValueError, match="EU-27"):
        _declare(incident, member_state="US")
    with pytest.raises(ValueError, match="precede"):
        _declare(incident, became_aware_at=incident["occurred_at"] - _DAY)

    _declare(incident)
    with pytest.raises(ValueError, match="already has an active"):
        _declare(incident)


def test_lifecycle_is_human_gated_and_terminal_states_are_final():
    incident = _incident()
    record = _declare(incident)
    due = record["report_due_at"]

    initial = air.record_submission(
        record["id"],
        kind="initial",
        submitted_by="compliance-officer",
        submitted_at=due - _DAY,
        reference="authority-ticket-311",
        expected_revision=record["revision"],
    )
    assert initial["status"] == "initial_reported"
    assert initial["submissions"][0]["late"] is False

    with pytest.raises(RecordConflict):
        air.record_submission(
            record["id"],
            kind="complete",
            submitted_by="compliance-officer",
            submitted_at=due,
            reference="stale-revision",
            expected_revision=record["revision"],
        )

    complete = air.record_submission(
        record["id"],
        kind="complete",
        submitted_by="compliance-officer",
        submitted_at=due + _DAY,
        reference="authority-ticket-311-final",
        expected_revision=initial["revision"],
    )
    assert complete["status"] == "complete_reported"
    # A late filing is recorded truthfully, never suppressed.
    assert complete["submissions"][1]["late"] is True
    assert air.report_clock(complete)["overdue"] is False

    with pytest.raises(ValueError, match="invalid"):
        air.record_submission(
            complete["id"],
            kind="initial",
            submitted_by="compliance-officer",
            submitted_at=due,
            reference="after-terminal",
            expected_revision=complete["revision"],
        )
    with pytest.raises(ValueError, match="invalid"):
        air.withdraw_declaration(
            complete["id"],
            rationale="Terminal states accept nothing further.",
            reviewer="risk-reviewer",
            expected_revision=complete["revision"],
        )


def test_withdrawal_requires_a_named_reviewer_and_frees_the_incident():
    incident = _incident()
    record = _declare(incident)
    with pytest.raises(ValueError, match="rationale"):
        air.withdraw_declaration(
            record["id"], rationale="", reviewer="risk-reviewer",
            expected_revision=record["revision"],
        )
    withdrawn = air.withdraw_declaration(
        record["id"],
        rationale="Review found no Art. 3(49) harm occurred.",
        reviewer="risk-reviewer",
        expected_revision=record["revision"],
    )
    assert withdrawn["status"] == "withdrawn"
    assert withdrawn["withdrawal"]["reviewer"] == "risk-reviewer"
    # A withdrawn declaration no longer blocks a corrected re-declaration.
    assert _declare(incident, category="death")["status"] == "declared"


def test_listing_sorts_by_urgency_and_overdue_surfaces():
    first = _incident()
    record = _declare(first, category="critical_infrastructure_disruption")
    aware = record["became_aware_at"]

    listed = air.list_declarations(now=aware + 3 * _DAY)
    assert listed[0]["id"] == record["id"]
    assert listed[0]["clock"]["overdue"] is True
    assert [row["id"] for row in air.overdue_declarations(now=aware + 3 * _DAY)] == [
        record["id"]
    ]
    assert air.overdue_declarations(now=aware + _DAY) == []
    with pytest.raises(ValueError, match="status"):
        air.list_declarations(status="pending")


def test_report_draft_carries_citations_routing_and_notice():
    incident = _incident()
    record = _declare(incident, category="death", widespread=True)
    draft = air.render_report(record["id"])

    assert "Art. 73(3)" in draft            # widespread forces the 2-day clock
    assert "Art. 3(49)(a)" in draft
    assert "Member State where the incident occurred: DE" in draft
    assert "Bundesnetzagentur market surveillance" in draft
    assert incident["id"] in draft
    assert "misrouted an emergency case" in draft
    assert air.REPORTING_NOTICE in draft
    # No GDPR Art. 33 clock leakage. A bare "72" substring is not assertable:
    # the draft embeds epoch timestamps and hex ids that contain it by chance.
    assert "72-hour" not in draft
    assert "72 hours" not in draft
    assert "Art. 33" not in draft
    assert "GDPR" not in draft
    with pytest.raises(KeyError):
        air.render_report("ASI-missing")


def test_reporting_is_off_by_default_and_fails_closed(tmp_path, monkeypatch):
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\nenable = true\n"
        "\n[model_risk_assurance]\nenable = true\ngate_promotions = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert air.enabled() is False
    with pytest.raises(air.AIIncidentReportingConfigError, match="off"):
        air.list_declarations()

    (tmp_path / "config.toml").write_text(
        "[ai_incident_reporting]\nenable = true\nextra = 1\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    with pytest.raises(air.AIIncidentReportingConfigError, match="unknown"):
        air.get_reporting_config()
