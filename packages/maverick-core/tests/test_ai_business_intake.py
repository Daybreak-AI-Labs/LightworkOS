"""Governed short-form AI business intake (G14)."""
from __future__ import annotations

import hashlib

import pytest
from maverick import ai_business_intake as abi
from maverick import model_risk_assurance as mra
from maverick.assessment import load_saved
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\n"
        "enable = true\n"
        "\n[model_risk_assurance]\n"
        "enable = true\n"
        "gate_promotions = true\n"
        "\n[ai_business_intake]\n"
        "enable = true\n",
        encoding="utf-8",
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _submission(
    *,
    name: str = "Hiring Recommendation Assistant",
    existing_asset_id: str = "",
    prohibited: list[str] | None = None,
    high_risk: list[str] | None = None,
    transparency: list[str] | None = None,
    automated: bool = True,
    human_oversight: bool = False,
    sensitive_data: bool = True,
) -> dict:
    value = {
        "use_case_name": name,
        "accountable_owner": "Morgan Owner",
        "business_unit": "People Operations",
        "purpose": "Recommend candidates for recruiter review.",
        "data_context": {
            "categories": ["employment", "personal"],
            "personal_data": True,
            "sensitive_data": sensitive_data,
            "source_summary": "Applicant records from the recruiting system.",
        },
        "deployment_context": {
            "stage": "pilot",
            "audience": "internal",
            "decision_role": "automated" if automated else "assistive",
            "human_oversight": human_oversight,
            "third_party": True,
            "safety_critical": False,
            "transparency_notice": "unknown",
        },
        "regulatory_context": {
            "prohibited_signals": prohibited or [],
            "high_risk_domains": high_risk or ["employment"],
            "transparency_signals": transparency or [],
        },
    }
    if existing_asset_id:
        value["existing_asset_id"] = existing_asset_id
    return value


def test_one_turn_submission_creates_review_work_without_legal_self_approval():
    ticks = iter((10.0, 10.027))
    service = abi.AIBusinessIntakeService(monotonic=lambda: next(ticks))

    with tenant_scope(tenant="alpha"):
        draft = service.start(
            idempotency_key="request-001",
            actor="business-requester",
            initial=_submission(),
        )
        replayed_start = service.start(
            idempotency_key="request-001",
            actor="business-requester",
            initial=_submission(),
        )
        assert replayed_start == draft
        assert draft["status"] == "draft"
        assert draft["progress"]["missing_fields"] == []

        routed = service.submit(
            draft["id"],
            actor="business-requester",
            operation_id="submit-001",
            expected_revision=draft["revision"],
        )

        assert routed["status"] == "pending_review"
        assert routed["classification"]["operational_risk_tier"] == "high"
        assert routed["classification"]["eu_ai_act_category"] == "undetermined"
        assert routed["classification"]["legal_determination"] is False
        assert routed["classification"]["human_review_required"] is True
        assert routed["human_review"] == {
            "required": True,
            "completed_by_intake": False,
            "legal_classification_asserted": False,
            "declaration_status_at_routing": "proposed",
            "assessment_status_at_routing": "pending_review",
        }

        observation = mra.get_observation(routed["asset_binding"]["asset_id"])
        declaration = mra.get_declaration(routed["asset_binding"]["asset_id"])
        assessment = load_saved(routed["assessment_binding"]["assessment_id"])
        assert observation is not None
        assert observation["identity"] == {
            "asset_type": "system",
            "source": "business_intake",
            "source_id": draft["id"],
        }
        assert declaration is not None
        assert declaration["status"] == "proposed"
        assert declaration["review"] is None
        assert declaration["eu_ai_act"]["category"] == "undetermined"
        assert declaration["eu_ai_act"]["human_reviewed"] is False
        assert assessment is not None
        assert assessment["status"] == "pending_review"
        assert assessment["answers"]["aira_high_risk"]["answer"] == "yes"
        assert assessment["answers"]["aira_bias"]["answer"] == "unknown"

        metrics = routed["burden_metrics"]
        assert metrics["machine_processing_ms"] == 27
        assert metrics["question_group_count"] == 7
        assert metrics["required_leaf_field_count"] == 17
        assert metrics["human_completion_verified"] is False
        assert metrics["under_three_minutes_claimed"] is False
        assert metrics["usability_benchmark_status"] == "not_evaluated"
        assert metrics["measurement_scope"] == "machine_processing_and_field_burden_only"

        # Replaying the completed submit operation is safe even though the
        # caller still has the draft revision.
        replayed = service.submit(
            draft["id"],
            actor="business-requester",
            operation_id="submit-001",
            expected_revision=draft["revision"],
        )
        assert replayed["revision"] == routed["revision"]
        assert len(mra.list_inventory()) == 1
        assert len(mra.list_declarations()) == 1


def test_conversational_save_resume_is_nested_cas_and_operation_idempotent():
    service = abi.AIBusinessIntakeService()
    with tenant_scope(tenant="alpha"):
        draft = service.start(
            idempotency_key="conversation-1",
            actor="requester",
            initial={"use_case_name": "Support Copilot"},
        )
        assert "accountable_owner" in draft["progress"]["missing_fields"]

        saved = service.save(
            draft["id"],
            patch={
                "accountable_owner": "Service Owner",
                "business_unit": "Customer Success",
                "purpose": "Draft answers for trained support representatives.",
                "data_context": {"categories": ["personal", "internal"]},
            },
            actor="requester",
            operation_id="answers-1",
            expected_revision=draft["revision"],
        )
        assert saved["submission"]["data_context"] == {
            "categories": ["internal", "personal"],
        }

        replay = service.save(
            draft["id"],
            patch={
                "accountable_owner": "Service Owner",
                "business_unit": "Customer Success",
                "purpose": "Draft answers for trained support representatives.",
                "data_context": {"categories": ["personal", "internal"]},
            },
            actor="requester",
            operation_id="answers-1",
            expected_revision=draft["revision"],
        )
        assert replay["revision"] == saved["revision"]
        assert replay["save_count"] == 1

        with pytest.raises(RecordConflict, match="different answers"):
            service.save(
                draft["id"],
                patch={"accountable_owner": "Different Owner"},
                actor="requester",
                operation_id="answers-1",
                expected_revision=saved["revision"],
            )

        with pytest.raises(RecordConflict, match="expected revision"):
            service.save(
                draft["id"],
                patch={"data_context": {"personal_data": True}},
                actor="requester",
                operation_id="answers-2",
                expected_revision=draft["revision"],
            )

        saved = service.save(
            draft["id"],
            patch={"data_context": {"personal_data": True, "sensitive_data": False}},
            actor="requester",
            operation_id="answers-2",
            expected_revision=saved["revision"],
        )
        assert saved["submission"]["data_context"] == {
            "categories": ["internal", "personal"],
            "personal_data": True,
            "sensitive_data": False,
        }
        summary = service.get(draft["id"])
        resumed = service.get(draft["id"], include_submission=True)
        assert summary is not None and "submission" not in summary
        assert resumed is not None and resumed["submission"] == saved["submission"]
        assert "idempotency_key_sha256" not in resumed
        assert "operation_receipts" not in resumed


def test_submit_reconciles_partial_side_effects_after_retry(monkeypatch):
    service = abi.AIBusinessIntakeService()
    original = service._ensure_declaration
    attempts = {"count": 0}

    def fail_once(*args, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("simulated stop after inventory observation")
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "_ensure_declaration", fail_once)
    with tenant_scope(tenant="alpha"):
        draft = service.start(
            idempotency_key="recoverable-submit",
            actor="requester",
            initial=_submission(),
        )
        with pytest.raises(RuntimeError, match="simulated stop"):
            service.submit(
                draft["id"],
                actor="requester",
                operation_id="submit-recoverable",
                expected_revision=draft["revision"],
            )
        staged = service.get(draft["id"])
        assert staged is not None and staged["status"] == "submitting"
        assert len(mra.list_inventory()) == 1
        assert mra.list_declarations() == []

        routed = service.submit(
            draft["id"],
            actor="requester",
            operation_id="submit-recoverable",
            expected_revision=draft["revision"],
        )
        assert routed["status"] == "pending_review"
        assert len(mra.list_inventory()) == 1
        assert len(mra.list_declarations()) == 1
        assert load_saved(routed["assessment_binding"]["assessment_id"]) is not None


def test_can_link_existing_system_without_replacing_its_observation():
    service = abi.AIBusinessIntakeService()
    officer = mra.ModelRiskAssuranceOfficer()
    with tenant_scope(tenant="alpha"):
        existing = officer.observe_asset(
            asset_type="system",
            source="cmdb",
            source_id="sys-418",
            display_name="Existing Claims Assistant",
            version_digest=_hex("existing-v1"),
            actor="inventory-operator",
            metadata={"environment": "pilot"},
            dependencies=[],
        )
        draft = service.start(
            idempotency_key="link-existing",
            actor="business-requester",
            initial=_submission(
                name="Claims Assistant Intake",
                existing_asset_id=existing["asset_id"],
                high_risk=["essential_services"],
            ),
        )
        routed = service.submit(
            draft["id"],
            actor="business-requester",
            operation_id="submit-existing",
            expected_revision=draft["revision"],
        )
        assert routed["asset_binding"]["asset_id"] == existing["asset_id"]
        assert routed["asset_binding"]["linked_existing"] is True
        assert len(mra.list_inventory()) == 1
        declaration = mra.get_declaration(existing["asset_id"])
        assert declaration is not None and declaration["status"] == "proposed"


def test_prohibited_signal_is_critical_triage_but_still_not_a_legal_assertion():
    service = abi.AIBusinessIntakeService()
    with tenant_scope(tenant="alpha"):
        draft = service.start(
            idempotency_key="prohibited-review",
            actor="requester",
            initial=_submission(
                prohibited=["social_scoring"],
                high_risk=[],
                automated=False,
                human_oversight=True,
                sensitive_data=False,
            ),
        )
        routed = service.submit(
            draft["id"],
            actor="requester",
            operation_id="submit-prohibited",
            expected_revision=draft["revision"],
        )
        assert routed["classification"]["screening_level"] == "critical"
        assert routed["classification"]["operational_risk_tier"] == "critical"
        assert routed["classification"]["eu_ai_act_category"] == "undetermined"
        assessment = load_saved(routed["assessment_binding"]["assessment_id"])
        assert assessment is not None
        assert assessment["answers"]["aira_prohibited"]["answer"] == "yes"


def test_tenant_isolation_and_explicit_scope_are_enforced():
    service = abi.AIBusinessIntakeService()
    with pytest.raises(abi.AIBusinessIntakeConfigError, match="explicit tenant"):
        service.start(idempotency_key="same-key", actor="requester")

    with tenant_scope(tenant="alpha"):
        alpha = service.start(
            idempotency_key="same-key",
            actor="requester",
            initial={"use_case_name": "Alpha Use Case"},
        )
        assert service.list() == [service.get(alpha["id"])]
    with tenant_scope(tenant="beta"):
        assert service.get(alpha["id"]) is None
        beta = service.start(
            idempotency_key="same-key",
            actor="requester",
            initial={"use_case_name": "Beta Use Case"},
        )
        assert beta["id"] == alpha["id"]
        assert beta["use_case_name"] == "Beta Use Case"
    with tenant_scope(tenant="alpha"):
        assert service.get(alpha["id"])["use_case_name"] == "Alpha Use Case"


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"unknown": "value"}, "unknown fields"),
        ({"purpose": "Bearer abcdefghijklmnopqrstuvwxyz"}, "credential"),
        (
            {"data_context": {"categories": ["none", "personal"]}},
            "cannot be combined",
        ),
        (
            {"data_context": {"personal_data": False, "sensitive_data": True}},
            "cannot be true",
        ),
        (
            {"regulatory_context": {"high_risk_domains": ["made_up_domain"]}},
            "high-risk domain",
        ),
    ],
)
def test_bounded_structured_input_rejects_unsafe_or_unknown_values(patch, message):
    service = abi.AIBusinessIntakeService()
    with tenant_scope(tenant="alpha"):
        with pytest.raises(ValueError, match=message):
            service.start(
                idempotency_key=f"invalid-{hashlib.sha256(repr(patch).encode()).hexdigest()}",
                actor="requester",
                initial=patch,
            )


def test_submit_refuses_incomplete_draft_without_changing_its_revision():
    service = abi.AIBusinessIntakeService()
    with tenant_scope(tenant="alpha"):
        draft = service.start(
            idempotency_key="incomplete",
            actor="requester",
            initial={"use_case_name": "Only a name"},
        )
        with pytest.raises(ValueError, match="incomplete"):
            service.submit(
                draft["id"],
                actor="requester",
                operation_id="submit-incomplete",
                expected_revision=draft["revision"],
            )
        current = service.get(draft["id"], include_submission=True)
        assert current is not None
        assert current["status"] == "draft"
        assert current["revision"] == draft["revision"]
        assert mra.list_inventory() == []


def test_feature_flag_requires_intake_and_model_risk_dependencies(tmp_path):
    from maverick import config

    assert abi.enabled() is True
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\n"
        "enable = true\n"
        "\n[model_risk_assurance]\n"
        "enable = true\n"
        "gate_promotions = true\n"
        "\n[ai_business_intake]\n"
        "enable = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert abi.enabled() is False
    with pytest.raises(abi.AIBusinessIntakeConfigError, match="disabled"):
        abi.require_enabled()
