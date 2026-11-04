"""Deterministic environment contracts for specialist-model improvement."""
from __future__ import annotations

import json
import re
import shutil

import pytest
from maverick.training import environments as env

EXPECTED_PACK_DIGESTS = {
    "article28_clause_v1": "fa2563569d4e826d62e7bf7afa35841a18f9c1ac316d05c090c137734bab5296",
    "dsar_routing_v1": "c3b7bdf723fc6c9f9436f98fee75612b53fa77f8613bfbdaead7896059f401eb",
    "privacy_assessment_v1": "0c3e8e149b41228e7b59f83adb5e6c854d96fb10212f50818157889891cf59f8",
}


def test_builtin_environment_packs_are_content_addressed_and_split_cleanly():
    assert env.list_environment_ids() == tuple(EXPECTED_PACK_DIGESTS)
    for environment_id, expected_digest in EXPECTED_PACK_DIGESTS.items():
        pack = env.load_environment(environment_id)
        assert pack.digest == expected_digest
        assert len(pack.cases) == 9
        assert {case.split for case in pack.cases} == {"train", "validation", "holdout"}
        assert len({case.case_id for case in pack.cases}) == len(pack.cases)
        assert not (
            {case.family_id for case in pack.split("train")}
            & {case.family_id for case in pack.split("holdout")}
        )


def test_pack_lock_rejects_file_tampering(tmp_path, monkeypatch):
    source = env.environment_pack_dir()
    for path in source.iterdir():
        shutil.copy2(path, tmp_path / path.name)
    tampered = tmp_path / "dsar_routing_v1.ndjson"
    tampered.write_bytes(tampered.read_bytes() + b"\n")
    monkeypatch.setattr(env, "environment_pack_dir", lambda: tmp_path)

    with pytest.raises(env.EnvironmentError, match="file digest differs"):
        env.load_environment("dsar_routing_v1")


def test_seed_packs_disclose_that_they_are_not_promotion_grade():
    report = env.promotion_readiness(env.load_environment("privacy_assessment_v1"))
    assert report["ready"] is False
    assert report["train_families"] == 3
    assert report["holdout_families"] == 3
    assert "need 20 independent holdout families" in " ".join(report["reasons"])
    assert "published seed data" in " ".join(report["reasons"])
    with pytest.raises(env.EnvironmentError, match="20"):
        env.promotion_readiness(
            env.load_environment("privacy_assessment_v1"),
            minimum_train_families=1,
        )


def test_family_relabeling_cannot_satisfy_promotion_floors():
    seed = env.load_environment("article28_clause_v1")
    cases = []
    for split in ("train", "holdout"):
        source = seed.split(split)[0]
        for index in range(20):
            raw = source.public_dict()
            citations = raw["required_citations"]
            selected_citations = (
                [citations[index % len(citations)]]
                if citations
                else []
            )
            raw.update({
                "case_id": f"{source.case_id}-clone-{index:02d}",
                "family_id": f"relabeled-{split}-{index:02d}",
                "source_id": f"clone-source-{split}-{index:02d}",
                "source_uri": f"https://example.test/{split}/{index:02d}",
                "license": f"synthetic clone metadata {index:02d}",
                "required_citations": selected_citations,
                "required_reason_codes": [f"clone-reason:{index:02d}"],
                "answer_visibility": (
                    "sealed" if split == "holdout" else "published"
                ),
            })
            if index % 2:
                raw["unordered_fields"] = [
                    field for field in reversed(raw["unordered_fields"])
                    if field != "citations"
                ]
                raw["expected"] = {
                    key: (
                        list(reversed(value))
                        if key in raw["unordered_fields"]
                        and isinstance(value, list)
                        else value
                    )
                    for key, value in raw["expected"].items()
                }
            cases.append(env.EnvironmentCase.from_mapping(raw))
    cloned = env.EnvironmentPack(
        environment_id=seed.environment_id,
        version=seed.version,
        description="relabeled clones are not independent proof",
        cases=tuple(cases),
    )

    report = env.promotion_readiness(cloned)

    assert report["ready"] is False
    assert report["train_families"] == 1
    assert report["holdout_families"] == 1
    assert "relabeling does not create independent evidence" in " ".join(
        report["reasons"],
    )


def test_exact_task_content_cannot_leak_from_train_into_holdout():
    seed = env.load_environment("privacy_assessment_v1")
    train = seed.split("train")[0]
    leaked_raw = train.public_dict()
    leaked_raw.update({
        "case_id": f"{train.case_id}-leaked-holdout",
        "family_id": f"{train.family_id}-renamed-holdout",
        "split": "holdout",
        "answer_visibility": "sealed",
    })
    leaked = env.EnvironmentCase.from_mapping(leaked_raw)
    pack = env.EnvironmentPack(
        environment_id=seed.environment_id,
        version=seed.version,
        description="cross-split leak",
        cases=(train, leaked),
    )

    with pytest.raises(env.EnvironmentError, match="identical prompt"):
        env.promotion_readiness(pack)


def test_reward_is_strict_deterministic_json_with_citation_evidence():
    case = env.load_environment("dsar_routing_v1").cases[0]
    exact = env.expected_output(case)
    result = env.score_output(case, json.dumps(exact))
    assert result.passed is True
    assert result.reward == 1.0

    missing_citation = env.score_output(case, case.expected)
    assert missing_citation.passed is False
    assert missing_citation.correctness == 1.0
    assert missing_citation.citation_score == 0.0

    fabricated_citation = env.score_output(
        case,
        {
            **case.expected,
            "citations": [{
                "source_id": case.source_id,
                "quote": "Return one JSON object",
                "start": 0,
                "end": 22,
            }],
        },
    )
    assert fabricated_citation.passed is False
    assert "exact source_id and span" in " ".join(fabricated_citation.reasons)

    extra_authority = env.score_output(case, {**exact, "auto_approve": True})
    assert extra_authority.passed is False
    assert extra_authority.reward <= 0.5

    malformed = env.score_output(case, "not-json")
    assert malformed.parsed is False
    assert malformed.reward == 0.0
    non_standard = env.score_output(
        case,
        '{"is_dsar": Infinity, "kind": "", "route": "", '
        '"deadline_days": null, "citations": [], "reason_codes": []}',
    )
    assert non_standard.parsed is False
    duplicate_field = env.score_output(
        case,
        '{"is_dsar": true, "is_dsar": true}',
    )
    assert duplicate_field.parsed is False


def test_nested_extras_and_duplicate_reason_codes_cannot_pass():
    nested = env.EnvironmentCase.from_mapping({
        "schema": env.CASE_SCHEMA,
        "case_id": "nested-001",
        "environment_id": "nested_contract_v1",
        "split": "holdout",
        "family_id": "nested-family-001",
        "prompt": "Return the decision. Text: synthetic source",
        "expected": {"decision": {"status": "review"}},
        "required_citations": [],
        "provenance": "synthetic",
        "source_uri": "https://example.test/synthetic-source",
        "license": "Lightwork synthetic benchmark",
        "data_classification": "public",
        "redaction_evidence": {"status": "not_applicable"},
        "answer_visibility": "published",
    })
    result = env.score_output(nested, {
        "decision": {"status": "review", "auto_approve": True},
        "citations": [],
        "reason_codes": [],
    })
    assert result.passed is False
    assert result.reward <= 0.5
    assert "unexpected nested" in " ".join(result.reasons)

    reasoned = env.load_environment("article28_clause_v1").cases[1]
    gold = env.expected_output(reasoned)
    gold["reason_codes"].append(gold["reason_codes"][0])
    result = env.score_output(reasoned, gold)
    assert result.passed is False
    assert "do not exactly match" in " ".join(result.reasons)


def test_set_like_result_fields_are_order_independent():
    case = env.load_environment("article28_clause_v1").cases[0]
    candidate = {
        **case.expected,
        "present": list(reversed(case.expected["present"])),
        "citations": list(reversed(env.expected_output(case)["citations"])),
        "reason_codes": list(reversed(case.required_reason_codes)),
    }
    assert env.score_output(case, candidate).passed is True


def test_evaluation_counts_missing_holdout_outputs_as_failures():
    pack = env.load_environment("article28_clause_v1")
    supplied = pack.split("holdout")[0]
    evaluation = env.evaluate_outputs(
        pack,
        {
            supplied.case_id: {
                **env.expected_output(supplied),
            },
            "not-a-holdout-case": {},
        },
    )
    assert len(evaluation.results) == 3
    assert evaluation.pass_rate == pytest.approx(1 / 4)
    assert evaluation.score < 1 / 3
    assert set(evaluation.missing_case_ids) == {"dpa-008", "dpa-009"}
    assert evaluation.extra_case_ids == ("not-a-holdout-case",)
    assert len(evaluation.digest) == 64


def test_arbitrary_pack_is_revalidated_and_evaluation_order_is_stable():
    pack = env.load_environment("dsar_routing_v1")
    reversed_pack = env.EnvironmentPack(
        environment_id=pack.environment_id,
        version=pack.version,
        description=pack.description,
        cases=tuple(reversed(pack.cases)),
    )
    outputs = {
        case.case_id: env.expected_output(case)
        for case in pack.split("holdout")
    }

    expected = env.evaluate_outputs(pack, outputs)
    reordered = env.evaluate_outputs(reversed_pack, outputs)

    assert reordered.digest == expected.digest
    assert [row.case_id for row in reordered.results] == sorted(outputs)

    malformed = env.EnvironmentCase(
        case_id="bad-direct-case",
        environment_id=pack.environment_id,
        split="holdout",
        family_id="bad-family",
        prompt="unvalidated",
        expected={"decision": "allow"},
    )
    with pytest.raises(env.EnvironmentError):
        env.validate_environment_pack(env.EnvironmentPack(
            environment_id=pack.environment_id,
            version=pack.version,
            description=pack.description,
            cases=(malformed,),
        ))


def test_empty_split_and_non_finite_boundary_time_are_refused(monkeypatch):
    pack = env.load_environment("privacy_assessment_v1")
    holdout_only = env.EnvironmentPack(
        environment_id=pack.environment_id,
        version=pack.version,
        description=pack.description,
        cases=pack.split("holdout"),
    )

    with pytest.raises(env.EnvironmentError, match="split .* is empty"):
        env.evaluate_outputs(holdout_only, {}, split="train")
    monkeypatch.setattr(env.time, "time", lambda: float("nan"))
    with pytest.raises(env.EnvironmentError, match="trusted training clock"):
        env.check_boundary(pack, "hosted")


def test_case_contract_rejects_duplicate_citations_and_reserved_fields():
    base = env.load_environment("dsar_routing_v1").cases[0].public_dict()
    duplicate = dict(base)
    duplicate["required_citations"] = ["Delete it", "Delete it"]
    with pytest.raises(env.EnvironmentError, match="must not contain duplicates"):
        env.EnvironmentCase.from_mapping(duplicate)

    reserved = dict(base)
    reserved["expected"] = {**base["expected"], "citations": []}
    with pytest.raises(env.EnvironmentError, match="reserved evidence fields"):
        env.EnvironmentCase.from_mapping(reserved)


def test_data_boundary_allows_only_public_seed_data_on_hosted_backend():
    pack = env.load_environment("privacy_assessment_v1")
    assert env.check_boundary(pack, "hosted").allowed is True
    cross_tenant = env.check_boundary(pack, "cross_tenant")
    assert cross_tenant.allowed is False
    assert "weight updates are not a privacy boundary" in cross_tenant.reasons[0]


def test_non_public_or_tenant_cases_need_explicit_identity_and_consent(
    monkeypatch,
):
    def consent(
        raw,
        *,
        record_id="consent-001",
        purpose="tenant_training",
        revoked=False,
    ):
        return {
            "schema": env.CONSENT_SCHEMA,
            "record_id": record_id,
            "tenant_id": "tenant-a",
            "case_id": raw["case_id"],
            "environment_id": raw["environment_id"],
            "admitted_content_sha256": env.admitted_content_sha256(raw),
            "allowed_purpose": purpose,
            "valid_until": 4_000_000_000,
            "retention_days": 365,
            "approved_by": "privacy-officer",
            "revoked": revoked,
        }

    def redaction(raw, *, evidence_id="redaction-001"):
        return {
            "schema": env.REDACTION_EVIDENCE_SCHEMA,
            "evidence_id": evidence_id,
            "case_id": raw["case_id"],
            "environment_id": raw["environment_id"],
            "status": "reviewed_no_detector_matches",
            "detector": "maverick.provable_redaction",
            "detector_version": "1.0.0",
            "detector_code_sha256": "a" * 64,
            "input_sha256": "b" * 64,
            "output_sha256": env.admitted_content_sha256(raw),
            "pass_count": 2,
            "residual_labels": [],
            "human_reviewed": True,
            "revoked": False,
        }

    raw = {
        "schema": env.CASE_SCHEMA,
        "case_id": "tenant-001",
        "environment_id": "tenant_privacy_v1",
        "split": "train",
        "family_id": "tenant-family-001",
        "prompt": "Return a JSON decision. Evidence: reviewed tenant example.",
        "evidence_text": "reviewed tenant example.",
        "expected": {"decision": "review"},
        "required_citations": [],
        "provenance": "tenant_trace",
        "source_uri": "https://customer.example/evidence/tenant-001",
        "license": "customer-controlled",
        "data_classification": "confidential",
        "answer_visibility": "sealed",
        "redaction_evidence": {"status": "not_applicable"},
    }
    with pytest.raises(env.EnvironmentError, match="structured consent"):
        env.EnvironmentCase.from_mapping(raw)

    case = env.EnvironmentCase.from_mapping({
        **raw,
        "consent": consent(raw),
        "redaction_evidence": redaction(raw),
    })
    raw_two = {
        **raw,
        "case_id": "tenant-002",
        "family_id": "tenant-family-002",
        "split": "holdout",
        "prompt": "Return a JSON decision. Evidence: another reviewed tenant example.",
        "evidence_text": "another reviewed tenant example.",
        "source_uri": "https://customer.example/evidence/tenant-002",
    }
    case_two = env.EnvironmentCase.from_mapping({
        **raw_two,
        "consent": consent(raw_two, record_id="consent-002"),
        "redaction_evidence": redaction(raw_two, evidence_id="redaction-002"),
    })
    pack = env.EnvironmentPack(
        environment_id="tenant_privacy_v1",
        version="1.0.0",
        description="tenant-local",
        cases=(case, case_two),
    )
    registry = env.TrustedEvidenceRegistry.from_mapping({
        "schema": env.TRUSTED_EVIDENCE_REGISTRY_SCHEMA,
        "registry_id": "privacy-authority-001",
        "revision": "snapshot-2026-07-23",
        "consent_records": {
            item.consent.record_id: item.consent.digest
            for item in pack.cases
            if item.consent is not None
        },
        "redaction_records": {
            item.redaction_evidence.evidence_id: item.redaction_evidence.digest
            for item in pack.cases
        },
    })
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setattr(env.time, "time", lambda: 2_000_000_000)
    with pytest.raises(env.EnvironmentError, match="authority|registry"):
        env.check_boundary(pack, "tenant_local")
    with pytest.raises(TypeError):
        env.check_boundary(pack, "tenant_local", trusted_evidence=registry)
    monkeypatch.setattr(
        env,
        "_server_trusted_evidence_registry",
        lambda: registry,
    )
    decision = env.check_boundary(pack, "tenant_local")
    assert decision.allowed is True
    assert decision.registry_digest == registry.digest
    assert decision.pack_digest == pack.digest
    assert dict(decision.admitted_content_digests) == {
        item.case_id: item.admitted_content_sha256 for item in pack.cases
    }
    assert len(decision.digest) == 64
    reordered = env.check_boundary(
        env.EnvironmentPack(
            environment_id=pack.environment_id,
            version=pack.version,
            description=pack.description,
            cases=tuple(reversed(pack.cases)),
        ),
        "tenant_local",
    )
    assert reordered.digest == decision.digest
    monkeypatch.setattr(env.time, "time", lambda: 2_100_000_000)
    later = env.check_boundary(pack, "tenant_local")
    assert later.evaluated_at != decision.evaluated_at
    assert later.digest == decision.digest
    monkeypatch.setattr(env.time, "time", lambda: 4_000_000_000)
    expired = env.check_boundary(pack, "tenant_local")
    assert expired.allowed is False
    assert expired.digest != decision.digest
    assert env.check_boundary(pack, "hosted").allowed is False

    with pytest.raises(env.EnvironmentError, match="allowed_purpose"):
        env.EnvironmentCase.from_mapping({
            **raw,
            "consent": consent(raw, purpose="no_training"),
            "redaction_evidence": redaction(raw),
        })

    revoked_raw = {**raw, "case_id": "tenant-003", "family_id": "tenant-family-003"}
    revoked_case = env.EnvironmentCase.from_mapping({
        **revoked_raw,
        "split": "holdout",
        "consent": consent(
            {**revoked_raw, "split": "holdout"},
            record_id="consent-003",
            revoked=True,
        ),
        "redaction_evidence": redaction(
            {**revoked_raw, "split": "holdout"},
            evidence_id="redaction-003",
        ),
    })
    revoked_pack = env.EnvironmentPack(
        environment_id="tenant_privacy_v1",
        version="1.0.0",
        description="revoked",
        cases=(revoked_case,),
    )
    revoked_registry = env.TrustedEvidenceRegistry.from_mapping({
        "schema": env.TRUSTED_EVIDENCE_REGISTRY_SCHEMA,
        "registry_id": "privacy-authority-001",
        "revision": "snapshot-revoked",
        "consent_records": {
            revoked_case.consent.record_id: revoked_case.consent.digest,
        },
        "redaction_records": {
            revoked_case.redaction_evidence.evidence_id:
                revoked_case.redaction_evidence.digest,
        },
    })
    monkeypatch.setattr(env.time, "time", lambda: 2_000_000_000)
    monkeypatch.setattr(
        env,
        "_server_trusted_evidence_registry",
        lambda: revoked_registry,
    )
    decision = env.check_boundary(revoked_pack, "tenant_local")
    assert decision.allowed is False
    assert "revoked" in " ".join(decision.reasons)
    with pytest.raises(env.EnvironmentError, match="sealed answers"):
        env.export_rows(pack, split="holdout")
    prompt_only = env.export_rows(
        pack,
        split="holdout",
        include_answers=False,
    )
    assert "answer" not in prompt_only[0]


def test_hosted_tenant_admission_rejects_self_asserted_or_forged_evidence(
    monkeypatch,
):
    content = {
        "schema": env.CASE_SCHEMA,
        "case_id": "hosted-tenant-001",
        "environment_id": "hosted_tenant_v1",
        "split": "holdout",
        "family_id": "hosted-family-001",
        "prompt": "Classify this tenant example. Text: reviewed redacted content.",
        "evidence_text": "reviewed redacted content.",
        "expected": {"decision": "review"},
        "required_citations": [],
        "provenance": "tenant_trace",
        "source_uri": "https://customer.example/evidence/hosted-tenant-001",
        "license": "customer-controlled",
        "data_classification": "public",
        "answer_visibility": "sealed",
    }
    admitted_digest = env.admitted_content_sha256(content)
    consent = {
        "schema": env.CONSENT_SCHEMA,
        "record_id": "hosted-consent-001",
        "tenant_id": "tenant-a",
        "case_id": content["case_id"],
        "environment_id": content["environment_id"],
        "admitted_content_sha256": admitted_digest,
        "allowed_purpose": "hosted_training",
        "valid_until": 4_000_000_000,
        "retention_days": 30,
        "approved_by": "privacy-officer",
        "revoked": False,
    }
    redaction = {
        "schema": env.REDACTION_EVIDENCE_SCHEMA,
        "evidence_id": "hosted-redaction-001",
        "case_id": content["case_id"],
        "environment_id": content["environment_id"],
        "status": "reviewed_no_detector_matches",
        "detector": "maverick.provable_redaction",
        "detector_version": "1.0.0",
        "detector_code_sha256": "a" * 64,
        "input_sha256": "b" * 64,
        "output_sha256": admitted_digest,
        "pass_count": 2,
        "residual_labels": [],
        "human_reviewed": True,
        "revoked": False,
    }
    authentic = env.EnvironmentCase.from_mapping({
        **content,
        "consent": consent,
        "redaction_evidence": redaction,
    })
    pack = env.EnvironmentPack(
        environment_id=content["environment_id"],
        version="1.0.0",
        description="hosted tenant admission",
        cases=(authentic,),
    )
    trusted = env.TrustedEvidenceRegistry.from_mapping({
        "schema": env.TRUSTED_EVIDENCE_REGISTRY_SCHEMA,
        "registry_id": "privacy-authority-001",
        "revision": "snapshot-authentic",
        "consent_records": {consent["record_id"]: authentic.consent.digest},
        "redaction_records": {
            redaction["evidence_id"]: authentic.redaction_evidence.digest,
        },
    })

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setattr(env.time, "time", lambda: 2_000_000_000)
    with pytest.raises(env.EnvironmentError, match="authority|registry"):
        env.check_boundary(pack, "hosted")
    with pytest.raises(TypeError):
        env.check_boundary(pack, "hosted", now=2_000_000_000)
    monkeypatch.setattr(
        env,
        "_server_trusted_evidence_registry",
        lambda: trusted,
    )
    assert env.check_boundary(pack, "hosted").allowed is True
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    with pytest.raises(env.EnvironmentError, match="matching active tenant"):
        env.check_boundary(pack, "hosted")
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")

    forged = env.EnvironmentCase.from_mapping({
        **content,
        "consent": {**consent, "approved_by": "attacker"},
        "redaction_evidence": redaction,
    })
    forged_pack = env.EnvironmentPack(
        environment_id=content["environment_id"],
        version="1.0.0",
        description="forged hosted tenant admission",
        cases=(forged,),
    )
    refused = env.check_boundary(forged_pack, "hosted")
    assert refused.allowed is False
    assert "consent differs from" in " ".join(refused.reasons)

    with pytest.raises(env.EnvironmentError, match="canonical admitted content"):
        env.EnvironmentCase.from_mapping({
            **content,
            "prompt": "Classify this tenant example. Text: attacker changed it.",
            "evidence_text": "attacker changed it.",
            "consent": consent,
            "redaction_evidence": redaction,
        })


def test_trusted_registry_is_loaded_only_from_active_tenant_private_state(
    tmp_path,
    monkeypatch,
):
    registry = env.TrustedEvidenceRegistry.from_mapping({
        "schema": env.TRUSTED_EVIDENCE_REGISTRY_SCHEMA,
        "registry_id": "privacy-authority-001",
        "revision": "protected-snapshot-001",
        "consent_records": {"consent-001": "a" * 64},
        "redaction_records": {"redaction-001": "b" * 64},
    })
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    path = env.trusted_evidence_registry_path()
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(registry.public_dict(), separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )

    loaded = env._server_trusted_evidence_registry()

    assert loaded == registry
    assert path.name == env.TRUSTED_EVIDENCE_REGISTRY_BASENAME
    assert "tenants" in path.parts


@pytest.mark.parametrize(
    "field",
    ["schema", "provenance", "data_classification", "license", "source_uri"],
)
def test_case_requires_explicit_security_and_provenance_fields(field):
    public = env.load_environment("dsar_routing_v1").cases[0].public_dict()
    public.pop(field)
    with pytest.raises(env.EnvironmentError, match="missing required fields"):
        env.EnvironmentCase.from_mapping(public)


def test_case_and_authority_schemas_reject_unknown_fields():
    public = env.load_environment("dsar_routing_v1").cases[0].public_dict()
    with pytest.raises(env.EnvironmentError, match="unknown fields"):
        env.EnvironmentCase.from_mapping({**public, "data_classificaton": "public"})

    tenant_content = {
        "schema": env.CASE_SCHEMA,
        "case_id": "strict-tenant-001",
        "environment_id": "strict_tenant_v1",
        "split": "holdout",
        "family_id": "strict-family-001",
        "prompt": "Return JSON. Text: reviewed tenant content.",
        "evidence_text": "reviewed tenant content.",
        "expected": {"decision": "review"},
        "required_citations": [],
        "provenance": "tenant_trace",
        "source_uri": "https://customer.example/evidence/strict-tenant-001",
        "license": "customer-controlled",
        "data_classification": "confidential",
        "answer_visibility": "sealed",
    }
    admitted_digest = env.admitted_content_sha256(tenant_content)
    consent = {
        "schema": env.CONSENT_SCHEMA,
        "record_id": "strict-consent-001",
        "tenant_id": "tenant-a",
        "case_id": tenant_content["case_id"],
        "environment_id": tenant_content["environment_id"],
        "admitted_content_sha256": admitted_digest,
        "allowed_purpose": "tenant_training",
        "valid_until": 4_000_000_000,
        "retention_days": 30,
        "approved_by": "privacy-officer",
        "revoked": False,
    }
    redaction = {
        "schema": env.REDACTION_EVIDENCE_SCHEMA,
        "evidence_id": "strict-redaction-001",
        "case_id": tenant_content["case_id"],
        "environment_id": tenant_content["environment_id"],
        "status": "reviewed_no_detector_matches",
        "detector": "maverick.provable_redaction",
        "detector_version": "1.0.0",
        "detector_code_sha256": "a" * 64,
        "input_sha256": "b" * 64,
        "output_sha256": admitted_digest,
        "pass_count": 1,
        "residual_labels": [],
        "human_reviewed": True,
        "revoked": False,
    }
    with pytest.raises(env.EnvironmentError, match="unknown fields"):
        env.EnvironmentCase.from_mapping({
            **tenant_content,
            "consent": {**consent, "approver": "attacker"},
            "redaction_evidence": redaction,
        })
    with pytest.raises(env.EnvironmentError, match="unknown fields"):
        env.EnvironmentCase.from_mapping({
            **tenant_content,
            "consent": consent,
            "redaction_evidence": {**redaction, "detector_trusted": True},
        })


def test_expected_rubric_rejects_nested_empty_objects():
    raw = env.load_environment("dsar_routing_v1").cases[0].public_dict()
    raw["expected"] = {"decision": {}}
    with pytest.raises(env.EnvironmentError, match="empty scored object"):
        env.EnvironmentCase.from_mapping(raw)

    raw["expected"] = {"decisions": [{"status": "review"}, {}]}
    with pytest.raises(env.EnvironmentError, match="empty scored object"):
        env.EnvironmentCase.from_mapping(raw)


def test_mapping_outputs_enforce_the_canonical_serialized_byte_limit():
    case = env.load_environment("dsar_routing_v1").cases[0]
    result = env.score_output(case, {
        **env.expected_output(case),
        "unexpected": "x" * (env.MAX_OUTPUT_BYTES + 1),
    })
    assert result.parsed is False
    assert result.reward == 0.0
    assert f"exceeds {env.MAX_OUTPUT_BYTES} bytes" in " ".join(result.reasons)


def test_export_rows_keep_hidden_answer_out_of_the_prompt():
    pack = env.load_environment("dsar_routing_v1")
    rows = env.export_rows(pack, split="holdout")
    assert len(rows) == 3
    for row in rows:
        assert row["answer"] not in row["prompt"][0]["content"]
        assert json.loads(row["answer"])["citations"]
        assert row["environment_digest"] == pack.digest


def test_pia_seed_labels_match_the_current_deterministic_assessment_engine():
    from maverick.assessment import AssessmentSession

    pack = env.load_environment("privacy_assessment_v1")
    for case in pack.cases:
        answers_blob = case.prompt.split("Answers:", 1)[1]
        answers = {}
        for pair in answers_blob.rstrip(".").split(";"):
            key, value = pair.strip().split("=", 1)
            answers[key] = value
        session = AssessmentSession(type="pia", subject=case.case_id)
        for question_id, answer in answers.items():
            session.record(question_id, answer)
        result = session.evaluate()
        actual = {
            "inherent_risk": result.inherent_risk,
            "residual_risk": result.residual_risk,
            "findings": [
                {"id": finding.question_id, "kind": finding.kind}
                for finding in result.findings
            ],
        }
        assert actual == case.expected


def test_dsar_seed_labels_match_the_current_deterministic_detector():
    from maverick.privacy_ops import detect_dsar

    pack = env.load_environment("dsar_routing_v1")
    for case in pack.cases:
        message = case.prompt.split("Message:", 1)[1].strip()
        hit = detect_dsar(message)
        actual = {
            "is_dsar": hit is not None,
            "kind": hit["kind"] if hit else "",
            "route": "privacy_review" if hit else "ordinary_support",
            "deadline_days": 30 if hit else None,
        }
        assert actual == case.expected


def test_article28_seed_labels_match_the_current_deterministic_checklist():
    from maverick import privacy_ops

    pack = env.load_environment("article28_clause_v1")
    for case in pack.cases:
        text = case.prompt.split("Text:", 1)[1].lower()
        present, missing, unclear = [], [], []
        for key, _requirement, _citation, _severity, patterns in privacy_ops.DPA_CHECKLIST:
            excerpt, prefix = privacy_ops._find(text, patterns, with_prefix=True)
            if excerpt is None:
                missing.append(key)
            elif re.search(r"\b(?:not|no|without|never|excluded?)\b[^.;]{0,20}$", prefix):
                unclear.append(key)
            else:
                present.append(key)
        assert {
            "present": present,
            "missing": missing,
            "unclear": unclear,
        } == case.expected
