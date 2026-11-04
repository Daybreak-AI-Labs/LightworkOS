from __future__ import annotations

import json

import pytest
from maverick import ai_vendor_portal as portal
from maverick import ai_vendor_risk as vendor_risk
from maverick.paths import tenant_scope


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
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
        "\n[ai_vendor_risk]\n"
        "enable = true\n"
        "portal_enable = true\n",
        encoding="utf-8",
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _answers() -> dict[str, dict[str, str]]:
    safe = {
        "aiv_provenance": "yes",
        "aiv_training_data": "yes",
        "aiv_subprocessors": "yes",
        "aiv_evaluation": "yes",
        "aiv_incidents": "no",
        "aiv_eu_role": "yes",
        "aiv_retention": "yes",
        "aiv_human_oversight": "yes",
    }
    return {
        question_id: {"answer": answer, "note": "Vendor attestation."}
        for question_id, answer in safe.items()
    }


def _invite(vendor: str = "Acme AI") -> dict:
    with tenant_scope(tenant="tenant-a"):
        return portal.create_invitation(
            vendor=vendor,
            actor="user:risk-owner",
            expires_in_seconds=3_600,
        )


def test_portal_gate_requires_both_feature_switches(tmp_path) -> None:
    from maverick import config

    assert portal.enabled() is True
    (tmp_path / "config.toml").write_text(
        "[ai_vendor_risk]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert portal.enabled() is False
    with tenant_scope(tenant="tenant-a"):
        with pytest.raises(portal.AIVendorPortalConfigError):
            portal.create_invitation(vendor="Acme", actor="user:risk-owner")


def test_invitation_discloses_token_once_and_questionnaire_is_exact(tmp_path) -> None:
    created = _invite()
    token = created["token"]
    assert token.startswith("aivp1.")
    assert token not in json.dumps(created["invitation"])

    with tenant_scope(tenant="tenant-a"):
        questionnaire = portal.questionnaire_for_token(token)
        invitations = portal.list_invitations()

    assert questionnaire["vendor"] == "Acme AI"
    assert questionnaire["questionnaire"]["template_digest"] == (
        created["invitation"]["questionnaire_digest"]
    )
    assert len(questionnaire["questionnaire"]["questions"]) == 8
    assert invitations == [created["invitation"]]
    serialized_files = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert token not in serialized_files


def test_submission_consumes_invitation_and_exact_retry_is_idempotent() -> None:
    created = _invite()
    token = created["token"]
    with tenant_scope(tenant="tenant-a"):
        first = portal.submit_response(
            token,
            answers=_answers(),
            respondent_ref="security-lead",
            attested=True,
            idempotency_key="response-1",
        )
        retry = portal.submit_response(
            token,
            answers=_answers(),
            respondent_ref="security-lead",
            attested=True,
            idempotency_key="response-1",
        )
        invitation = portal.get_invitation(
            created["invitation"]["invitation_id"]
        )

    assert first == retry
    assert first["status"] == "pending_import"
    assert first["respondent_ref"] == "security-lead"
    assert invitation["status"] == "consumed"
    assert invitation["submission_id"] == first["submission_id"]
    assert "token_sha256" not in json.dumps(invitation)
    assert "idempotency" not in json.dumps(first)


def test_consumed_invitation_rejects_changed_response_or_key() -> None:
    created = _invite()
    token = created["token"]
    with tenant_scope(tenant="tenant-a"):
        portal.submit_response(
            token,
            answers=_answers(),
            respondent_ref="security-lead",
            attested=True,
            idempotency_key="response-1",
        )
        changed = _answers()
        changed["aiv_evaluation"]["answer"] = "no"
        with pytest.raises(portal.AIVendorPortalConflict):
            portal.submit_response(
                token,
                answers=changed,
                respondent_ref="security-lead",
                attested=True,
                idempotency_key="response-1",
            )
        with pytest.raises(portal.AIVendorPortalConflict):
            portal.submit_response(
                token,
                answers=_answers(),
                respondent_ref="security-lead",
                attested=True,
                idempotency_key="response-2",
            )


def test_token_is_tenant_bound_and_revocation_is_immediate() -> None:
    created = _invite()
    token = created["token"]
    with tenant_scope(tenant="tenant-b"):
        with pytest.raises(portal.AIVendorPortalAuthError):
            portal.questionnaire_for_token(token)
    with tenant_scope(tenant="tenant-a"):
        revoked = portal.revoke_invitation(
            created["invitation"]["invitation_id"],
            reason="vendor engagement ended",
            actor="user:risk-owner",
            expected_revision=created["invitation"]["revision"],
        )
        assert revoked["status"] == "revoked"
        with pytest.raises(portal.AIVendorPortalAuthError):
            portal.questionnaire_for_token(token)


def test_expired_invitation_and_unsafe_answers_fail_closed(monkeypatch) -> None:
    created = _invite()
    token = created["token"]
    future = created["invitation"]["expires_at"] + 1
    monkeypatch.setattr(
        portal._INVITATIONS,
        "authoritative_time",
        lambda: future,
    )
    with tenant_scope(tenant="tenant-a"):
        with pytest.raises(portal.AIVendorPortalAuthError):
            portal.questionnaire_for_token(token)

    created = _invite("Safe Notes")
    unsafe = _answers()
    unsafe["aiv_provenance"]["note"] = (
        "Use sk-proj-abcdefghijklmnopqrstuvwxyz123456 to inspect the model."
    )
    with tenant_scope(tenant="tenant-a"):
        with pytest.raises(ValueError, match="secret material"):
            portal.submit_response(
                created["token"],
                answers=unsafe,
                respondent_ref="security-lead",
                attested=True,
                idempotency_key="unsafe",
            )


def test_import_creates_review_required_vendor_attestation_and_recovers() -> None:
    created = _invite()
    with tenant_scope(tenant="tenant-a"):
        submission = portal.submit_response(
            created["token"],
            answers=_answers(),
            respondent_ref="security-lead",
            attested=True,
            idempotency_key="response-import",
        )
        imported = portal.import_submission(
            submission["submission_id"],
            actor="user:risk-owner",
            expected_revision=submission["revision"],
        )
        replay = portal.import_submission(
            submission["submission_id"],
            actor="user:risk-owner",
            expected_revision=submission["revision"],
        )
        resolved = vendor_risk.find_vendor_assessment_by_attestation(
            submission["response_sha256"]
        )

    assessment = imported["assessment"]
    assert imported["idempotent_replay"] is False
    assert replay["idempotent_replay"] is True
    assert assessment["status"] == "pending_review"
    assert assessment["review_required"] is True
    assert resolved["id"] == assessment["id"]
    assert {
        source["kind"] for source in assessment["answer_sources"].values()
    } == {"vendor_attested"}
    assert {
        source["submission_sha256"]
        for source in assessment["answer_sources"].values()
    } == {submission["response_sha256"]}


def test_submission_requires_complete_attested_pseudonymous_response() -> None:
    created = _invite()
    token = created["token"]
    incomplete = _answers()
    incomplete.pop("aiv_eu_role")
    with tenant_scope(tenant="tenant-a"):
        with pytest.raises(ValueError, match="every current"):
            portal.submit_response(
                token,
                answers=incomplete,
                respondent_ref="security-lead",
                attested=True,
                idempotency_key="incomplete",
            )
        with pytest.raises(ValueError, match="explicitly attest"):
            portal.submit_response(
                token,
                answers=_answers(),
                respondent_ref="security-lead",
                attested=False,
                idempotency_key="not-attested",
            )
        with pytest.raises(ValueError, match="pseudonymous"):
            portal.submit_response(
                token,
                answers=_answers(),
                respondent_ref="person@example.com",
                attested=True,
                idempotency_key="pii-respondent",
            )
