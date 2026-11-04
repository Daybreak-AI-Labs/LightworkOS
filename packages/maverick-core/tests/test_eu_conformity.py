"""FRIA, Annex IV, and Art. 43 route workflows: human-gated, cite-exact.

The assertions that matter: a FRIA completes only with all six Art. 27(1)
elements and a named assessor; the Art. 27(2) update obligation reopens a
completed assessment; Art. 43's forbidden route combinations are refused at
the boundary; and a substantial modification (but never a pre-determined,
documented change) forces reassessment.
"""
from __future__ import annotations

import time

import pytest
from maverick import config
from maverick import eu_conformity as euc
from maverick.paths import tenant_scope


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
        "[eu_conformity]\nenable = true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


_ASSET = "MAA-" + "a" * 32


def _complete_fria():
    record = euc.open_fria(_ASSET, context="triage-deployment", actor="dpo")
    for element in euc.FRIA_ELEMENTS:
        record = euc.assert_fria_element(
            record["id"], element,
            content=f"Assessed statement for {element}.",
            actor="dpo",
            expected_revision=record["revision"],
        )
    return euc.complete_fria(
        record["id"], assessor="dpo", expected_revision=record["revision"],
    )


def test_workflows_are_off_by_default(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert euc.enabled() is False
    with pytest.raises(euc.EUConformityConfigError, match="enable"):
        euc.open_fria(_ASSET, context="x", actor="dpo")


def test_fria_completion_requires_every_element_and_a_named_assessor():
    record = euc.open_fria(_ASSET, context="triage-deployment", actor="dpo")
    assert record["status"] == "draft"
    assert set(record["elements"]) == set(euc.FRIA_ELEMENTS)
    # Opening again returns the same record, never a duplicate.
    assert euc.open_fria(_ASSET, context="triage-deployment", actor="dpo")["id"] == record["id"]

    with pytest.raises(ValueError, match="element must be one of"):
        euc.assert_fria_element(
            record["id"], "vibes", content="x", actor="dpo",
            expected_revision=record["revision"],
        )
    partial = euc.assert_fria_element(
        record["id"], "process_description",
        content="Used inside the underwriting triage process only.",
        actor="dpo",
        expected_revision=record["revision"],
    )
    with pytest.raises(euc.EUConformityError, match="not asserted"):
        euc.complete_fria(
            partial["id"], assessor="dpo", expected_revision=partial["revision"],
        )

    completed = _complete_fria()
    assert completed["status"] == "completed"
    assert completed["assessor"] == "dpo"
    element = completed["elements"]["risks_of_harm"]
    assert element["citation"] == "Art. 27(1)(d)"
    assert element["asserted_by"] == "dpo"

    # A completed assessment refuses silent edits (Art. 27(2) gate).
    with pytest.raises(euc.EUConformityError, match="outdated"):
        euc.assert_fria_element(
            completed["id"], "process_description", content="drift",
            actor="dpo", expected_revision=completed["revision"],
        )


def test_fria_update_obligation_and_notification_are_recorded():
    completed = _complete_fria()
    notified = euc.record_fria_notification(
        completed["id"],
        authority="Bundesnetzagentur market surveillance",
        submitted_by="dpo",
        submitted_at=time.time(),
        reference="fria-filing-311",
        expected_revision=completed["revision"],
    )
    assert notified["notification"]["citation"] == "Art. 27(3)"

    outdated = euc.mark_fria_outdated(
        notified["id"],
        reason="The affected user categories changed after rollout to minors.",
        actor="dpo",
        expected_revision=notified["revision"],
    )
    assert outdated["status"] == "outdated"
    refreshed = euc.assert_fria_element(
        outdated["id"], "affected_categories",
        content="Now includes applicants under 18.",
        actor="dpo",
        expected_revision=outdated["revision"],
    )
    recompleted = euc.complete_fria(
        refreshed["id"], assessor="dpo", expected_revision=refreshed["revision"],
    )
    assert recompleted["status"] == "completed"

    draft = euc.render_fria(recompleted["id"])
    assert "Art. 27(1)(f)" in draft
    assert "under 18" in draft
    assert euc.NON_CERTIFICATION_NOTICE in draft
    assert [row["id"] for row in euc.list_frias(status="completed")] == [
        recompleted["id"]
    ]


def test_annex_iv_checklist_tracks_all_nine_items_with_citations():
    record = euc.open_annex_iv(_ASSET, actor="ml-lead")
    status = euc.annex_iv_status(record["id"])
    assert status["total"] == 9
    assert status["asserted"] == 0
    assert status["complete"] is False

    for item in euc.ANNEX_IV_ITEMS:
        record = euc.assert_annex_iv_item(
            record["id"], item,
            reference=f"docs/annex-iv/{item}.md",
            actor="ml-lead",
            expected_revision=record["revision"],
        )
    status = euc.annex_iv_status(record["id"])
    assert status["complete"] is True

    rendered = euc.render_annex_iv(record["id"])
    for citation in ("Annex IV(1)", "Annex IV(5)", "Annex IV(9)"):
        assert citation in rendered
    assert "Article 9" in rendered
    assert "Article 47" in rendered
    assert euc.NON_CERTIFICATION_NOTICE in rendered
    with pytest.raises(ValueError, match="item must be one of"):
        euc.assert_annex_iv_item(
            record["id"], "marketing_gloss", reference="x", actor="ml-lead",
            expected_revision=record["revision"],
        )


def test_art_43_routes_refuse_forbidden_combinations():
    # Point 1 without standards or specs cannot self-assess.
    with pytest.raises(euc.EUConformityError, match="Art. 43\\(1\\)"):
        euc.record_assessment_route(
            _ASSET,
            route="internal_control_annex_vi",
            annex_iii_point=1,
            harmonised_standards_applied=False,
            common_specifications_applied=False,
            rationale="Attempted self-assessment without coverage.",
            actor="quality-lead",
        )
    # Points 2-8 never involve a notified body.
    with pytest.raises(euc.EUConformityError, match="Art. 43\\(2\\)"):
        euc.record_assessment_route(
            _ASSET,
            route="notified_body_annex_vii",
            annex_iii_point=4,
            harmonised_standards_applied=True,
            common_specifications_applied=False,
            rationale="Wrongly routed to a notified body.",
            actor="quality-lead",
        )
    with pytest.raises(ValueError, match="no Annex III point"):
        euc.record_assessment_route(
            _ASSET,
            route="sectoral_annex_i",
            annex_iii_point=2,
            harmonised_standards_applied=False,
            common_specifications_applied=False,
            rationale="Sectoral products carry no Annex III point.",
            actor="quality-lead",
        )

    recorded = euc.record_assessment_route(
        _ASSET,
        route="internal_control_annex_vi",
        annex_iii_point=1,
        harmonised_standards_applied=True,
        common_specifications_applied=False,
        rationale="Harmonised standards under Art. 40 applied in full.",
        actor="quality-lead",
    )
    assert recorded["status"] == "recorded"
    assert recorded["decided_by"] == "quality-lead"


def test_substantial_modification_forces_reassessment_unless_predetermined():
    recorded = euc.record_assessment_route(
        _ASSET,
        route="internal_control_annex_vi",
        annex_iii_point=4,
        harmonised_standards_applied=True,
        common_specifications_applied=False,
        rationale="Point 4 internal control.",
        actor="quality-lead",
    )
    predetermined = euc.mark_substantial_modification(
        _ASSET,
        reason="Scheduled quarterly retrain documented in Annex IV(6).",
        actor="quality-lead",
        expected_revision=recorded["revision"],
        predetermined=True,
    )
    assert predetermined["status"] == "recorded"

    reopened = euc.mark_substantial_modification(
        _ASSET,
        reason="The system now serves a new user population.",
        actor="quality-lead",
        expected_revision=predetermined["revision"],
    )
    assert reopened["status"] == "reassessment_required"
    assert reopened["modifications"][-1]["predetermined"] is False


def test_list_assessment_routes_filters_by_status():
    other = "MAA-" + "b" * 32
    euc.record_assessment_route(
        _ASSET,
        route="internal_control_annex_vi",
        annex_iii_point=4,
        harmonised_standards_applied=True,
        common_specifications_applied=False,
        rationale="Point 4 internal control.",
        actor="quality-lead",
    )
    flagged = euc.record_assessment_route(
        other,
        route="internal_control_annex_vi",
        annex_iii_point=5,
        harmonised_standards_applied=False,
        common_specifications_applied=False,
        rationale="Point 5 internal control.",
        actor="quality-lead",
    )
    euc.mark_substantial_modification(
        other,
        reason="A new data source changed the system's behaviour.",
        actor="quality-lead",
        expected_revision=flagged["revision"],
    )

    rows = euc.list_assessment_routes()
    assert [row["asset_id"] for row in rows] == sorted([_ASSET, other])
    flagged_rows = euc.list_assessment_routes(status="reassessment_required")
    assert [row["asset_id"] for row in flagged_rows] == [other]
    with pytest.raises(ValueError, match="status"):
        euc.list_assessment_routes(status="nope")


def test_pmm_plan_record_and_review():
    recorded = euc.record_pmm_plan(
        _ASSET, plan_reference="wiki/models/credit/pmm-plan", actor="quality-lead",
    )
    assert recorded["citation"] == "Art. 72(1)"
    assert "2026-02-02" in recorded["template_note"]

    with pytest.raises(ValueError, match="no_change review cannot move"):
        euc.record_pmm_review(
            _ASSET, outcome="no_change", actor="quality-lead",
            expected_revision=recorded["revision"],
            plan_reference="wiki/elsewhere",
        )
    reviewed = euc.record_pmm_review(
        _ASSET, outcome="no_change", actor="quality-lead",
        expected_revision=recorded["revision"],
    )
    assert len(reviewed["reviews"]) == 1
    moved = euc.record_pmm_review(
        _ASSET, outcome="plan_updated", actor="quality-lead",
        expected_revision=reviewed["revision"],
        plan_reference="wiki/models/credit/pmm-plan-v2",
    )
    assert moved["plan_reference"] == "wiki/models/credit/pmm-plan-v2"
    assert len(moved["reviews"]) == 2

    with pytest.raises(KeyError):
        euc.record_pmm_review(
            "MAA-" + "c" * 32, outcome="no_change", actor="quality-lead",
            expected_revision=1,
        )
    assert [row["asset_id"] for row in euc.list_pmm_plans()] == [_ASSET]


def test_registration_refuses_the_wrong_registry():
    with pytest.raises(euc.EUConformityError, match=r"Art\. 49\(1\)"):
        euc.record_registration(
            _ASSET, basis="provider_high_risk", registry="national",
            reference="NAT-1", actor="counsel",
        )
    with pytest.raises(euc.EUConformityError, match=r"Art\. 49\(5\)"):
        euc.record_registration(
            _ASSET, basis="annex_iii_point_2_national", registry="eu_database",
            reference="EUDB-1", actor="counsel",
        )
    with pytest.raises(ValueError, match="basis"):
        euc.record_registration(
            _ASSET, basis="nope", registry="eu_database",
            reference="EUDB-1", actor="counsel",
        )
    recorded = euc.record_registration(
        _ASSET, basis="annex_iii_point_2_national", registry="national",
        reference="NAT-2026-9", actor="counsel",
    )
    assert recorded["citation"] == "Art. 49(5)"
    assert euc.get_registration(_ASSET)["reference"] == "NAT-2026-9"
    assert len(euc.list_registrations()) == 1


def test_ifu_checklist_tracks_all_six_items():
    record = euc.open_ifu(_ASSET, actor="counsel")
    assert euc.open_ifu(_ASSET, actor="counsel")["id"] == record["id"]
    with pytest.raises(ValueError, match="item"):
        euc.assert_ifu_item(
            record["id"], "nope", reference="wiki", actor="counsel",
            expected_revision=record["revision"],
        )
    revision = record["revision"]
    for item in euc.IFU_ITEMS:
        saved = euc.assert_ifu_item(
            record["id"], item, reference=f"handbook#{item}", actor="counsel",
            expected_revision=revision,
        )
        revision = saved["revision"]
    state = euc.ifu_status(record["id"])
    assert state["asserted"] == state["total"] == 6
    assert state["complete"] is True
    assert euc.get_ifu(_ASSET)["items"]["log_collection"]["citation"] == "Art. 13(3)(f)"
    assert [row["asset_id"] for row in euc.list_ifu_checklists()] == [_ASSET]


def test_registers_are_tenant_scoped():
    with tenant_scope(tenant="alpha"):
        _complete_fria()
        assert len(euc.list_frias()) == 1
    with tenant_scope(tenant="beta"):
        assert euc.list_frias() == []
        assert euc.get_assessment_route(_ASSET) is None


def test_gpai_register_tracks_provider_obligations():
    record = euc.open_gpai(_ASSET, systemic_risk=False, actor="counsel")
    assert euc.open_gpai(_ASSET, systemic_risk=False, actor="counsel")["id"] == record["id"]
    state = euc.gpai_status(record["id"])
    assert state["total"] == 4
    assert state["exempt"] == []

    revision = record["revision"]
    for obligation in euc.GPAI_OBLIGATIONS:
        saved = euc.assert_gpai_obligation(
            record["id"], obligation,
            reference=f"vault#{obligation}", actor="counsel",
            expected_revision=revision,
        )
        revision = saved["revision"]
    complete = euc.gpai_status(record["id"])
    assert complete["complete"] is True

    with pytest.raises(ValueError, match="obligation"):
        euc.assert_gpai_obligation(
            record["id"], "model_evaluation",
            reference="vault", actor="counsel", expected_revision=revision,
        )


def test_gpai_systemic_risk_adds_art55_and_blocks_the_exemption():
    other = "MAA-" + "d" * 32
    with pytest.raises(euc.EUConformityError, match=r"Art\. 53\(2\)"):
        euc.open_gpai(
            other, systemic_risk=True, open_source_exempt=True, actor="counsel",
        )
    record = euc.open_gpai(other, systemic_risk=True, actor="counsel")
    state = euc.gpai_status(record["id"])
    assert state["total"] == 8
    assert "model_evaluation" in state["missing"]

    exempt_asset = "MAA-" + "e" * 32
    exempted = euc.open_gpai(
        exempt_asset, systemic_risk=False, open_source_exempt=True,
        actor="counsel",
    )
    exempt_state = euc.gpai_status(exempted["id"])
    assert exempt_state["exempt"] == sorted(euc.GPAI_OPEN_SOURCE_EXEMPT)
    assert exempt_state["missing"] == ["copyright_policy", "training_content_summary"]
    assert len(euc.list_gpai_registers()) >= 2
    assert euc.get_gpai(exempt_asset)["open_source_exempt"] is True


def test_fria_four_eyes_review_requires_a_different_completed_reviewer():
    completed = _complete_fria()
    with pytest.raises(euc.EUConformityError, match="other than the assessor"):
        euc.record_fria_review(
            completed["id"], outcome="concur", reviewer="dpo",
            expected_revision=completed["revision"],
        )
    reviewed = euc.record_fria_review(
        completed["id"], outcome="objections", reviewer="second-counsel",
        expected_revision=completed["revision"],
        notes="The affected-categories answer omits contractors.",
    )
    assert reviewed["reviews"][-1]["outcome"] == "objections"
    assert reviewed["status"] == "completed"

    draft = euc.open_fria("MAA-" + "b" * 32, context="draft-only", actor="dpo")
    with pytest.raises(euc.EUConformityError, match="completed FRIA only"):
        euc.record_fria_review(
            draft["id"], outcome="concur", reviewer="second-counsel",
            expected_revision=draft["revision"],
        )


def test_deployer_register_tracks_the_applicable_art26_duties():
    record = euc.open_deployer_register(
        _ASSET, workplace_use=True, requires_dpia=True, actor="ops",
    )
    keys = set(record["obligations"])
    # Always-applicable + oversight + the two flagged conditionals.
    assert "use_per_instructions" in keys
    assert "log_retention" in keys
    assert "human_oversight_assignment" in keys
    assert "worker_information" in keys
    assert "dpia_information" in keys
    # Unflagged conditionals stay out of the register entirely.
    assert "registration_check" not in keys
    assert "input_data_control" not in keys
    # Idempotent open.
    assert euc.open_deployer_register(_ASSET, actor="ops")["id"] == record["id"]

    state = euc.deployer_status(record["id"])
    assert state["total"] == 8
    assert state["asserted"] == 0
    assert state["oversight_persons"] == []


def test_deployer_oversight_must_name_natural_persons():
    record = euc.open_deployer_register(_ASSET, actor="ops")
    # The oversight duty cannot be asserted with a bare reference.
    with pytest.raises(euc.EUConformityError, match="26\\(2\\)"):
        euc.assert_deployer_obligation(
            record["id"], "human_oversight_assignment",
            reference="doc://oversight", actor="ops",
            expected_revision=record["revision"],
        )
    with pytest.raises(ValueError, match="named natural person"):
        euc.assign_deployer_oversight(
            record["id"], persons=[], reference="doc://oversight",
            actor="ops", expected_revision=record["revision"],
        )
    with pytest.raises(ValueError, match="distinct"):
        euc.assign_deployer_oversight(
            record["id"], persons=["Ada", "ada"], reference="doc://oversight",
            actor="ops", expected_revision=record["revision"],
        )
    saved = euc.assign_deployer_oversight(
        record["id"], persons=["Ada Lovelace", "Grace Hopper"],
        reference="doc://oversight-competence", actor="ops",
        expected_revision=record["revision"],
    )
    state = euc.deployer_status(saved["id"])
    assert state["oversight_persons"] == ["Ada Lovelace", "Grace Hopper"]


def test_deployer_assertions_complete_the_register():
    record = euc.open_deployer_register(_ASSET, actor="ops")
    with pytest.raises(ValueError, match="obligation must be one of"):
        euc.assert_deployer_obligation(
            record["id"], "vibes", reference="x", actor="ops",
            expected_revision=record["revision"],
        )
    # Conditional duty not flagged at open: refused.
    with pytest.raises(ValueError, match="obligation must be one of"):
        euc.assert_deployer_obligation(
            record["id"], "worker_information", reference="x", actor="ops",
            expected_revision=record["revision"],
        )
    current = record
    for key in ("use_per_instructions", "operation_monitoring",
                "log_retention", "affected_person_information",
                "authority_cooperation"):
        current = euc.assert_deployer_obligation(
            current["id"], key, reference=f"doc://{key}", actor="ops",
            expected_revision=current["revision"],
        )
    current = euc.assign_deployer_oversight(
        current["id"], persons=["Ada Lovelace"], reference="doc://oversight",
        actor="ops", expected_revision=current["revision"],
    )
    state = euc.deployer_status(current["id"])
    assert state["complete"] is True
    assert state["missing"] == []
    assert euc.list_deployer_registers()[0]["asset_id"] == _ASSET


def test_status_projections_from_loaded_rows_match_the_store_reads():
    # The list surfaces (dashboard panels, CLI lists) project posture from
    # rows they already hold; the pure helpers must agree byte-for-byte
    # with the id-addressed reads.
    gpai = euc.open_gpai(_ASSET, systemic_risk=True, actor="ops")
    euc.assert_gpai_obligation(
        gpai["id"], "technical_documentation",
        reference="doc://gpai/tech.pdf", actor="ops",
        expected_revision=gpai["revision"],
    )
    deployer = euc.open_deployer_register(
        _ASSET, workplace_use=True, actor="ops",
    )
    for row in euc.list_gpai_registers():
        assert euc.gpai_status_from_record(row) == euc.gpai_status(row["id"])
    for row in euc.list_deployer_registers():
        assert (euc.deployer_status_from_record(row)
                == euc.deployer_status(row["id"]))
    assert deployer["id"].startswith("ECY-")
