"""Focused coverage for the governed AI literacy register."""
from __future__ import annotations

import copy
import hashlib
import json
import time

import pytest
from maverick import ai_literacy as literacy
from maverick import config
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

lit = literacy

NOW = 1_800_000_000.0
DAY = 24 * 60 * 60


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _register(clock: list[float]) -> literacy.AILiteracyRegister:
    return literacy.AILiteracyRegister(clock=lambda: clock[0])


def test_feature_gate_is_explicit_and_default_off(_isolate):
    from maverick import config

    assert literacy.enabled() is False
    (_isolate / "config.toml").write_text(
        "[ai_literacy]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert literacy.enabled() is True


def _requirement(
    register: literacy.AILiteracyRegister,
    *,
    version: str = "2026.1",
    expected_revision: int = 0,
    idempotency_key: str = "requirement-v1",
    title: str = "Safe operation of decision-support AI",
) -> dict:
    return register.upsert_requirement(
        "operators.safe_ai",
        title=title,
        role_ids=["case_operator"],
        system_ids=["SYS-risk-copilot"],
        provider_id="internal_lms",
        content_id="safe-ai-operations",
        content_version=version,
        validity_days=30,
        due_within_days=10,
        expected_revision=expected_revision,
        idempotency_key=idempotency_key,
        actor="literacy-admin",
    )


def _assignment(
    register: literacy.AILiteracyRegister,
    person_id: str = "person-001",
    *,
    expected_revision: int = 0,
    idempotency_key: str = "assignment-v1",
    role_ids: list[str] | None = None,
    system_ids: list[str] | None = None,
) -> dict:
    return register.set_person_assignments(
        person_id,
        role_ids=["case_operator"] if role_ids is None else role_ids,
        system_ids=["SYS-risk-copilot"] if system_ids is None else system_ids,
        expected_revision=expected_revision,
        idempotency_key=idempotency_key,
        actor="people-ops",
    )


def _completion(
    register: literacy.AILiteracyRegister,
    person_id: str = "person-001",
    *,
    completed_at: float,
    expires_at: float,
    idempotency_key: str = "completion-001",
    version: str = "2026.1",
    provider_id: str = "internal_lms",
    provider_record_id: str = "lms-record-private-001",
) -> dict:
    return register.record_completion(
        person_id,
        "operators.safe_ai",
        provider_id=provider_id,
        content_id="safe-ai-operations",
        content_version=version,
        completed_at=completed_at,
        expires_at=expires_at,
        provider_evidence_sha256=_digest("completion-certificate"),
        provider_record_id=provider_record_id,
        idempotency_key=idempotency_key,
        actor="lms-sync",
    )


def test_explicit_tenant_scope_and_pseudonymous_storage(_isolate):
    clock = [NOW]
    register = _register(clock)

    with pytest.raises(literacy.AILiteracyStateError, match="explicit tenant"):
        _requirement(register)

    direct_identifier = "jane.doe@example.test"
    with tenant_scope(tenant="tenant-alpha"):
        requirement = _requirement(register)
        assignment = _assignment(register, direct_identifier)
        assert requirement["tenant_ref"].startswith("TEN-")
        assert assignment["subject_ref"].startswith("PRN-")
        assert direct_identifier not in json.dumps(assignment)

    persisted = b"\n".join(
        path.read_bytes() for path in _isolate.rglob("*") if path.is_file()
    )
    assert direct_identifier.encode() not in persisted

    with tenant_scope(tenant="tenant-beta"):
        assert register.get_requirement("operators.safe_ai") is None
        assert register.get_person_assignment(direct_identifier) is None


def test_requirement_and_assignment_cas_and_idempotency():
    clock = [NOW]
    register = _register(clock)
    with tenant_scope(tenant="tenant-alpha"):
        first = _requirement(register)
        replay = _requirement(register)
        assert first["revision"] == replay["revision"] == 1

        with pytest.raises(literacy.AILiteracyIdempotencyConflict):
            _requirement(register, title="Different input under the same key")
        with pytest.raises(RecordConflict):
            _requirement(
                register,
                version="2026.2",
                idempotency_key="requirement-v2",
            )

        clock[0] += DAY
        second = _requirement(
            register,
            version="2026.2",
            expected_revision=first["revision"],
            idempotency_key="requirement-v2",
        )
        assert second["revision"] == 2
        assert second["effective_at"] == clock[0]

        assigned = _assignment(register)
        first_role_date = assigned["role_assignments"][0]["assigned_at"]
        clock[0] += DAY
        expanded = _assignment(
            register,
            expected_revision=assigned["revision"],
            idempotency_key="assignment-v2",
            role_ids=["case_operator", "model_owner"],
            system_ids=["SYS-risk-copilot"],
        )
        assert expanded["revision"] == 2
        assert expanded["role_assignments"][0]["assigned_at"] == first_role_date
        assert expanded["role_assignments"][1]["assigned_at"] == clock[0]
        assert _assignment(
            register,
            expected_revision=assigned["revision"],
            idempotency_key="assignment-v2",
            role_ids=["case_operator", "model_owner"],
            system_ids=["SYS-risk-copilot"],
        )["revision"] == 2


def test_gap_computation_completion_expiry_and_content_version_change(_isolate):
    clock = [NOW]
    register = _register(clock)
    person_id = "training.user@example.test"
    provider_record_id = "provider-record-with-personal-correlation"
    with tenant_scope(tenant="tenant-alpha"):
        first_requirement = _requirement(register)
        _assignment(register, person_id)

        due = register.compute_gaps(person_id, as_of=NOW)
        assert due["summary"] == {
            "applicable_requirements": 1,
            "satisfied": 0,
            "waived": 0,
            "due": 1,
            "overdue": 0,
            "coverage_gaps": 1,
        }
        overdue = register.compute_gaps(person_id, as_of=NOW + 11 * DAY)
        assert overdue["requirements"][0]["state"] == "overdue"
        assert overdue["requirements"][0]["gap_reason"] == "completion_missing"

        clock[0] = NOW + 12 * DAY
        completion = _completion(
            register,
            person_id,
            completed_at=clock[0],
            expires_at=clock[0] + 20 * DAY,
            provider_record_id=provider_record_id,
        )
        replay = _completion(
            register,
            person_id,
            completed_at=clock[0],
            expires_at=clock[0] + 20 * DAY,
            provider_record_id=provider_record_id,
        )
        assert completion["revision"] == replay["revision"] == 1
        assert provider_record_id not in json.dumps(completion)
        assert register.compute_gaps(
            person_id,
            as_of=clock[0] + DAY,
        )["requirements"][0]["state"] == "satisfied"

        expired = register.compute_gaps(person_id, as_of=clock[0] + 21 * DAY)
        assert expired["requirements"][0]["state"] == "overdue"
        assert expired["requirements"][0]["gap_reason"] == "completion_expired"

        with pytest.raises(literacy.AILiteracyIdempotencyConflict):
            _completion(
                register,
                person_id,
                completed_at=clock[0],
                expires_at=clock[0] + 19 * DAY,
                provider_record_id=provider_record_id,
            )

        clock[0] += DAY
        _requirement(
            register,
            version="2026.2",
            expected_revision=first_requirement["revision"],
            idempotency_key="requirement-v2",
        )
        changed = register.compute_gaps(person_id, as_of=clock[0])
        assert changed["requirements"][0]["state"] == "due"
        assert changed["requirements"][0]["gap_reason"] == "current_content_not_completed"

    persisted = b"\n".join(
        path.read_bytes() for path in _isolate.rglob("*") if path.is_file()
    )
    assert person_id.encode() not in persisted
    assert provider_record_id.encode() not in persisted


def test_reviewed_waiver_expiration_revocation_and_self_review_rejection():
    clock = [NOW]
    register = _register(clock)
    with tenant_scope(tenant="tenant-alpha"):
        _requirement(register)
        _assignment(register)
        with pytest.raises(ValueError, match="self-reviewed"):
            register.grant_waiver(
                "person-001",
                "operators.safe_ai",
                kind="exemption",
                reviewer_id="person-001",
                reason_code="equivalent_training",
                decision_basis_sha256=_digest("review-file"),
                starts_at=NOW,
                expires_at=NOW + DAY,
                idempotency_key="self-waiver",
                actor="risk-reviewer",
            )

        waiver = register.grant_waiver(
            "person-001",
            "operators.safe_ai",
            kind="exemption",
            reviewer_id="reviewer-001",
            reason_code="equivalent_training",
            decision_basis_sha256=_digest("review-file"),
            starts_at=NOW,
            expires_at=NOW + DAY,
            idempotency_key="waiver-001",
            actor="risk-reviewer",
        )
        status = register.compute_gaps("person-001", as_of=NOW)
        assert status["requirements"][0]["state"] == "waived"
        assert status["requirements"][0]["waiver"]["reviewer_ref"].startswith("PRN-")

        expired = register.compute_gaps("person-001", as_of=NOW + 2 * DAY)
        assert expired["requirements"][0]["state"] == "due"
        assert expired["requirements"][0]["gap_reason"] == "waiver_expired"

        revoked = register.revoke_waiver(
            waiver["id"],
            reviewer_id="reviewer-002",
            expected_revision=waiver["revision"],
            idempotency_key="revoke-001",
            actor="risk-manager",
        )
        replay = register.revoke_waiver(
            waiver["id"],
            reviewer_id="reviewer-002",
            expected_revision=waiver["revision"],
            idempotency_key="revoke-001",
            actor="risk-manager",
        )
        assert revoked["status"] == "revoked"
        assert replay["revision"] == revoked["revision"] == 2


def test_evidence_export_is_pseudonymous_bounded_and_tamper_evident():
    clock = [NOW]
    register = _register(clock)
    person_id = "jane.doe@example.test"
    reviewer_id = "alex.reviewer@example.test"
    idempotency_key = "private-import-run-001"
    with tenant_scope(tenant="tenant-alpha"):
        _requirement(register)
        _assignment(register, person_id)
        register.grant_waiver(
            person_id,
            "operators.safe_ai",
            kind="waiver",
            reviewer_id=reviewer_id,
            reason_code="leave_or_absence",
            decision_basis_sha256=_digest("approved-leave-record"),
            starts_at=NOW,
            expires_at=NOW + 5 * DAY,
            idempotency_key=idempotency_key,
            actor="people-risk-reviewer",
        )
        exported = register.export_evidence(as_of=NOW)

    rendered = json.dumps(exported, sort_keys=True)
    assert exported["summary"]["waived"] == 1
    assert exported["stores_direct_person_identifiers"] is False
    assert person_id not in rendered
    assert reviewer_id not in rendered
    assert idempotency_key not in rendered
    assert "idempotency_receipts" not in rendered
    assert literacy.verify_evidence_export(exported)
    tampered = copy.deepcopy(exported)
    tampered["summary"]["waived"] = 0
    assert not literacy.verify_evidence_export(tampered)


def test_historical_completion_is_evidence_but_wrong_provider_and_expiry_are_rejected():
    clock = [NOW]
    register = _register(clock)
    with tenant_scope(tenant="tenant-alpha"):
        _requirement(register)
        _assignment(register)
        stale = _completion(
            register,
            completed_at=NOW,
            expires_at=NOW + DAY,
            version="old-version",
        )
        assert stale["content"]["content_version"] == "old-version"
        status = register.compute_gaps("person-001", as_of=NOW)
        assert status["requirements"][0]["gap_reason"] == "current_content_not_completed"
        with pytest.raises(ValueError, match="provider and content identity"):
            _completion(
                register,
                completed_at=NOW,
                expires_at=NOW + DAY,
                provider_id="other_lms",
                idempotency_key="wrong-provider",
            )
        with pytest.raises(ValueError, match="validity period"):
            _completion(
                register,
                completed_at=NOW,
                expires_at=NOW + 31 * DAY,
            )


# Compatibility coverage for the role-oriented governance-workspace API.
_DAY = 86_400


def _enable_role_api(tmp_path) -> None:
    (tmp_path / "config.toml").write_text(
        "[ai_literacy]\nenable = true\n", encoding="utf-8",
    )
    config.reset_config_cache()


def _require_underwriting():
    return lit.set_role_requirement(
        "underwriting_operator",
        [
            {"key": "ai-fundamentals", "title": "AI fundamentals", "validity_days": 365},
            {"key": "model-limits", "title": "Model limitations briefing",
             "validity_days": None},
        ],
        actor="compliance-lead",
    )


def test_plane_status_separates_authoritative_and_compatibility_records(_isolate):
    _enable_role_api(_isolate)
    with tenant_scope(tenant="tenant-alpha"):
        canonical_only = lit.literacy_plane_status(now=NOW)
        assert canonical_only["authoritative_plane"] == "canonical"
        assert canonical_only["canonical"]["available"] is True
        assert canonical_only["reconciliation_required"] is False

        _requirement(lit.default_register)
        with_canonical = lit.literacy_plane_status(now=NOW)
        assert with_canonical["canonical"]["requirement_count"] == 1
        assert with_canonical["role_compatibility"]["records_present"] is False
        assert with_canonical["reconciliation_required"] is False

        _require_underwriting()
        lit.assign_roles(
            "analyst@example.com",
            ["underwriting_operator"],
            actor="hr",
        )
        mixed = lit.literacy_plane_status(now=NOW)
        assert mixed["mixed_planes"] is True
        assert mixed["reconciliation_required"] is True
        assert mixed["role_compatibility"]["authoritative_for_compliance"] is False
        assert mixed["role_compatibility"]["stores_direct_person_identifiers"] is True
        assert mixed["canonical"]["stores_direct_person_identifiers"] is False


def test_plane_status_fails_closed_when_canonical_tenant_is_unavailable(_isolate):
    _enable_role_api(_isolate)
    _require_underwriting()
    status = lit.literacy_plane_status(now=NOW)
    assert status["canonical"]["available"] is False
    assert status["role_compatibility"]["records_present"] is True
    assert status["reconciliation_required"] is True


def test_register_is_off_by_default_and_rejects_hostile_input(tmp_path):
    assert issubclass(lit.AILiteracyConfigError, lit.AILiteracyError)
    assert issubclass(lit.AILiteracyStateError, lit.AILiteracyError)
    assert issubclass(lit.AILiteracyIdempotencyConflict, lit.AILiteracyError)
    assert {
        lit.ROLE_REQUIREMENT_SCHEMA,
        lit.ROLE_ASSIGNMENT_SCHEMA,
        lit.ROLE_COMPLETION_SCHEMA,
    }.isdisjoint(
        {
            lit.REQUIREMENT_SCHEMA,
            lit.ASSIGNMENT_SCHEMA,
            lit.COMPLETION_SCHEMA,
        }
    )
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert lit.enabled() is False
    with pytest.raises(lit.AILiteracyConfigError, match="enable"):
        lit.literacy_gaps()

    (tmp_path / "config.toml").write_text(
        "[ai_literacy]\nenable = true\nextra = 1\n", encoding="utf-8",
    )
    config.reset_config_cache()
    with pytest.raises(lit.AILiteracyConfigError, match="unknown"):
        lit.get_ai_literacy_config()

    (tmp_path / "config.toml").write_text(
        "[ai_literacy]\nenable = true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    with pytest.raises(ValueError, match="identifier"):
        lit.set_role_requirement("bad role!", [], actor="ops")
    with pytest.raises(ValueError, match="1-64"):
        lit.set_role_requirement("role", [], actor="ops")
    with pytest.raises(ValueError, match="unknown training keys"):
        lit.set_role_requirement(
            "role", [{"key": "k", "title": "T", "url": "https://x"}], actor="ops",
        )
    with pytest.raises(ValueError, match="unique"):
        lit.set_role_requirement(
            "role",
            [{"key": "k", "title": "T"}, {"key": "k", "title": "T2"}],
            actor="ops",
        )
    with pytest.raises(ValueError, match="between 1 and 3650"):
        lit.set_role_requirement(
            "role", [{"key": "k", "title": "T", "validity_days": 0}], actor="ops",
        )


def test_requirements_and_assignments_are_named_cas_assertions(_isolate):
    _enable_role_api(_isolate)
    requirement = _require_underwriting()
    assert requirement["set_by"] == "compliance-lead"
    assert [row["key"] for row in requirement["trainings"]] == [
        "ai-fundamentals", "model-limits",
    ]

    # A second blind create conflicts; the update path needs the revision.
    with pytest.raises(RecordConflict):
        _require_underwriting()
    updated = lit.set_role_requirement(
        "underwriting_operator",
        [{"key": "ai-fundamentals", "title": "AI fundamentals", "validity_days": 180}],
        actor="compliance-lead",
        expected_revision=requirement["revision"],
    )
    assert updated["revision"] > requirement["revision"]

    with pytest.raises(ValueError, match="no recorded requirement"):
        lit.assign_roles("analyst@example.com", ["ghost_role"], actor="hr-ops")
    assignment = lit.assign_roles(
        "analyst@example.com", ["underwriting_operator"], actor="hr-ops",
    )
    assert assignment["assigned_by"] == "hr-ops"
    assert assignment["roles"] == ["underwriting_operator"]


def test_gaps_derive_missing_expired_and_current_states(_isolate):
    _enable_role_api(_isolate)
    _require_underwriting()
    lit.assign_roles("analyst@example.com", ["underwriting_operator"], actor="hr")
    now = time.time()

    gaps = lit.literacy_gaps(now=now)
    assert gaps["counts"] == {"current": 0, "expired": 0, "missing": 2}
    person = gaps["persons"][0]
    assert person["gap_count"] == 2

    lit.record_completion(
        "analyst@example.com", "ai-fundamentals",
        completed_at=now - 400 * _DAY,
        evidence_ref="lms:course/ai-fundamentals/attempt-1",
        actor="lms-feed",
    )
    lit.record_completion(
        "analyst@example.com", "model-limits",
        completed_at=now - 400 * _DAY,
        evidence_ref="lms:course/model-limits/attempt-1",
        actor="lms-feed",
    )
    gaps = lit.literacy_gaps(now=now)
    states = {row["training"]: row for row in gaps["persons"][0]["trainings"]}
    # 365-day validity lapsed; the no-validity training never expires.
    assert states["ai-fundamentals"]["status"] == "expired"
    assert states["model-limits"]["status"] == "current"
    assert gaps["counts"] == {"current": 1, "expired": 1, "missing": 0}
    assert gaps["regulation"]["article"] == "Art. 4"

    refreshed = lit.record_completion(
        "analyst@example.com", "ai-fundamentals",
        completed_at=now - _DAY,
        evidence_ref="lms:course/ai-fundamentals/attempt-2",
        actor="lms-feed",
    )
    assert len(refreshed["history"]) == 1
    assert refreshed["history"][0]["evidence_ref"].endswith("attempt-1")
    gaps = lit.literacy_gaps(now=now)
    assert gaps["counts"] == {"current": 2, "expired": 0, "missing": 0}


def test_completions_refuse_future_dates_and_keep_bounded_history(_isolate):
    _enable_role_api(_isolate)
    _require_underwriting()
    with pytest.raises(ValueError, match="future-dated"):
        lit.record_completion(
            "analyst@example.com", "ai-fundamentals",
            completed_at=time.time() + 3_600,
            evidence_ref="lms:x",
            actor="lms-feed",
        )
    now = time.time()
    for attempt in range(25):
        lit.record_completion(
            "analyst@example.com", "ai-fundamentals",
            completed_at=now - (30 - attempt) * _DAY,
            evidence_ref=f"lms:attempt-{attempt}",
            actor="lms-feed",
        )
    row = lit.record_completion(
        "analyst@example.com", "ai-fundamentals",
        completed_at=now,
        evidence_ref="lms:final",
        actor="lms-feed",
    )
    assert len(row["history"]) == 20


def test_evidence_export_is_bounded_json_with_citation_and_notice(_isolate):
    _enable_role_api(_isolate)
    _require_underwriting()
    lit.assign_roles("analyst@example.com", ["underwriting_operator"], actor="hr")
    exported = json.loads(lit.export_evidence(now=time.time()))
    assert exported["regulation"]["regulation"] == "Regulation (EU) 2024/1689"
    assert exported["regulation"]["applicable_since"] == "2025-02-02"
    assert exported["notice"] == lit.NON_CERTIFICATION_NOTICE
    assert exported["roles"][0]["role"] == "underwriting_operator"
    assert exported["counts"]["missing"] == 2
    assert exported["persons"][0]["person"] == "analyst@example.com"


def test_register_is_tenant_scoped(_isolate):
    _enable_role_api(_isolate)
    with tenant_scope(tenant="alpha"):
        _require_underwriting()
        lit.assign_roles("analyst@example.com", ["underwriting_operator"], actor="hr")
        assert lit.literacy_gaps()["person_count"] == 1
    with tenant_scope(tenant="beta"):
        assert lit.literacy_gaps()["person_count"] == 0
        assert lit.list_requirements() == []
