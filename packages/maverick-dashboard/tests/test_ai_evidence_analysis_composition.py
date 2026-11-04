from __future__ import annotations

import contextlib
import gc
import hashlib
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import ai_evidence_analysis as evidence
from maverick import ai_evidence_local_parsers as local_parsers
from maverick_dashboard import ai_evidence_analysis_authority_api as authority_api
from maverick_dashboard import ai_evidence_analysis_composition as composition

TENANT = "tenant-evidence"
NOW = 1_900_000_000.0


class Clock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config(
    *,
    media: list[str] | None = None,
    max_artifact_bytes: int = 4_096,
    max_artifacts_per_case: int = 2,
    max_authority_records: int = 100_000,
    max_extracted_text_bytes: int = 4_096,
    retention_seconds: int = 7_200,
) -> dict[str, object]:
    return {
        "evidence_gateway": {"enable": True},
        "ai_evidence_analysis": {
            "enable": True,
            "enabled_media_types": media or ["text"],
            "max_artifact_bytes": max_artifact_bytes,
            "max_artifacts_per_case": max_artifacts_per_case,
            "max_authority_records": max_authority_records,
            "max_extracted_text_bytes": max_extracted_text_bytes,
            "retention_seconds": retention_seconds,
        },
    }


def _parser_sandbox() -> dict[str, object]:
    return {
        "enable": True,
        "mode": "bubblewrap",
        "launcher": "/usr/bin/bwrap",
        "launcher_sha256": "b" * 64,
        "launcher_version": "0.11.0",
    }


def _criterion() -> evidence.EvidenceCriterion:
    raw = evidence.EvidenceCriterion(
        criterion_id="criterion-access",
        revision=1,
        control_ref="control-access",
        control_revision=2,
        control_sha256=_digest("control-access-2"),
        legal_basis_ref="basis-access",
        legal_basis_revision=3,
        legal_basis_sha256=_digest("basis-access-3"),
        stakeholder_requirement_ref="stakeholder-access",
        stakeholder_requirement_revision=4,
        stakeholder_requirement_sha256=_digest("stakeholder-access-4"),
        expected_fact_code="FACT.access",
        gap_code="gap-access",
        remediation_code="remediate-access",
        weight_bps=10_000,
        criterion_sha256="0" * 64,
    )
    return replace(raw, criterion_sha256=evidence.criterion_sha256(raw))


def _build(
    tmp_path: Path,
    *,
    config: dict[str, object] | None = None,
    clock: Clock | None = None,
    bootstrap: bool = True,
) -> composition.EvidenceAnalysisComposition:
    return composition.build_ai_evidence_analysis_composition(
        tenant_id=TENANT,
        config=config or _config(),
        registry_path=tmp_path / "authorities.sqlite3",
        analysis_path=tmp_path / "analyses.sqlite3",
        clock=clock or Clock(),
        bootstrap_local_adapters=bootstrap,
    )


def _enroll_round_trip_authorities(
    material: composition.EvidenceAnalysisComposition,
    raw: bytes,
) -> tuple[
    evidence.EvidenceArtifactAuthority,
    evidence.EvidenceCriteriaAuthority,
]:
    artifact, _ = material.registry.enroll_artifact(
        artifact_id="artifact-one",
        case_ref="case-one",
        media_type=evidence.MEDIA_TEXT,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        byte_length=len(raw),
        source_ref="source-vault",
        source_revision=1,
        acquired_at=NOW - 10,
        valid_until=NOW + 3_600,
    )
    criteria, _ = material.registry.enroll_criteria(
        criteria_set_id="criteria-one",
        revision=1,
        criteria=(_criterion(),),
        valid_until=NOW + 3_600,
    )
    material.registry.enroll_reviewer(
        reviewer_ref="reviewer-two",
        capabilities=("approve", "reject", "revoke"),
        revision=1,
        valid_until=NOW + 3_600,
    )
    return artifact, criteria


def test_settings_parse_every_limit_and_fail_closed() -> None:
    settings = composition.ai_evidence_analysis_settings(
        _config(media=["pdf", "text"], max_artifacts_per_case=3)
    )
    assert settings is not None
    assert settings.enabled_media_types == (
        evidence.MEDIA_PDF,
        evidence.MEDIA_TEXT,
    )
    assert settings.max_artifacts_per_case == 3
    assert settings.max_authority_records == 100_000
    assert settings.artifact_limit(evidence.MEDIA_TEXT) == 4_096

    disabled = _config()
    disabled["ai_evidence_analysis"]["enable"] = False  # type: ignore[index]
    assert composition.ai_evidence_analysis_settings(disabled) is None

    without_gateway = _config()
    without_gateway["evidence_gateway"] = {"enable": False}
    with pytest.raises(composition.AIEvidenceAnalysisCompositionError, match="evidence_gateway"):
        composition.ai_evidence_analysis_settings(without_gateway)

    invalid_media = _config(media=["text", "text"])
    with pytest.raises(composition.AIEvidenceAnalysisCompositionError, match="allowlist"):
        composition.ai_evidence_analysis_settings(invalid_media)

    unknown = _config()
    unknown["ai_evidence_analysis"]["surprise"] = True  # type: ignore[index]
    with pytest.raises(composition.AIEvidenceAnalysisCompositionError, match="unsupported"):
        composition.ai_evidence_analysis_settings(unknown)

    unbounded = _config(max_authority_records=3)
    with pytest.raises(
        composition.AIEvidenceAnalysisCompositionError,
        match="max_authority_records",
    ):
        composition.ai_evidence_analysis_settings(unbounded)


def test_settings_gate_governed_ocr_and_legacy_xls_independently() -> None:
    default = composition.ai_evidence_analysis_settings(_config(media=["png", "text"]))
    assert default is not None
    assert default.ocr is None
    assert default.legacy_xls is None

    missing_gate = _config(media=["xls", "text"])
    with pytest.raises(composition.AIEvidenceAnalysisCompositionError, match="legacy_xls"):
        composition.ai_evidence_analysis_settings(missing_gate)

    valid_xls = _config(media=["xls", "text"])
    valid_xls["ai_evidence_analysis"]["parser_sandbox"] = _parser_sandbox()  # type: ignore[index]
    valid_xls["ai_evidence_analysis"]["legacy_xls"] = {  # type: ignore[index]
        "enable": True,
        "xlrd_version": "2.0.2",
        "xlrd_manifest_sha256": "c" * 64,
        "olefile_version": "0.47",
        "olefile_manifest_sha256": "d" * 64,
        "max_output_bytes": 4_096,
    }
    selected = composition.ai_evidence_analysis_settings(valid_xls)
    assert selected is not None
    assert selected.legacy_xls is not None
    assert selected.legacy_xls.xlrd_version == "2.0.2"

    invalid_ocr = _config(media=["text"])
    invalid_ocr["ai_evidence_analysis"]["parser_sandbox"] = _parser_sandbox()  # type: ignore[index]
    invalid_ocr["ai_evidence_analysis"]["ocr"] = {  # type: ignore[index]
        "enable": True,
        "executable": "/opt/tesseract/bin/tesseract",
        "executable_sha256": "a" * 64,
        "tesseract_version": "5.4.1",
        "traineddata_path": "/opt/tesseract/share/tessdata/eng.traineddata",
        "traineddata_sha256": "c" * 64,
        "runtime_library_paths": ["/opt/tesseract/lib/libtesseract.so"],
        "runtime_libraries_sha256": "d" * 64,
        "pillow_version": "12.3.0",
        "pillow_manifest_sha256": "e" * 64,
    }
    with pytest.raises(composition.AIEvidenceAnalysisCompositionError, match="jpeg or png"):
        composition.ai_evidence_analysis_settings(invalid_ocr)


def test_registry_enforces_case_media_size_and_append_only_revocation(tmp_path: Path) -> None:
    material = _build(
        tmp_path,
        config=_config(max_artifacts_per_case=1, max_artifact_bytes=1_024),
    )
    registry = material.registry
    first, first_revision = registry.enroll_artifact(
        artifact_id="artifact-one",
        case_ref="case-one",
        media_type=evidence.MEDIA_TEXT,
        content_sha256=_digest("one"),
        byte_length=100,
        source_ref="source-one",
        source_revision=1,
        acquired_at=NOW - 1,
        valid_until=NOW + 100,
    )
    assert first_revision == 1
    assert registry.artifact_case_ref("artifact-one") == "case-one"

    with pytest.raises(
        composition.AIEvidenceAnalysisAuthorityConflict,
        match="artifact limit",
    ):
        registry.enroll_artifact(
            artifact_id="artifact-two",
            case_ref="case-one",
            media_type=evidence.MEDIA_TEXT,
            content_sha256=_digest("two"),
            byte_length=100,
            source_ref="source-two",
            source_revision=1,
            acquired_at=NOW - 1,
            valid_until=NOW + 100,
        )

    with pytest.raises(composition.AIEvidenceAnalysisCompositionError, match="disabled"):
        registry.enroll_artifact(
            artifact_id="artifact-pdf",
            case_ref="case-two",
            media_type=evidence.MEDIA_PDF,
            content_sha256=_digest("pdf"),
            byte_length=100,
            source_ref="source-pdf",
            source_revision=1,
            acquired_at=NOW - 1,
            valid_until=NOW + 100,
        )

    with pytest.raises(composition.AIEvidenceAnalysisCompositionError, match="outside"):
        registry.enroll_artifact(
            artifact_id="artifact-large",
            case_ref="case-two",
            media_type=evidence.MEDIA_TEXT,
            content_sha256=_digest("large"),
            byte_length=1_025,
            source_ref="source-large",
            source_revision=1,
            acquired_at=NOW - 1,
            valid_until=NOW + 100,
        )

    revoked, second_revision = registry.revoke_artifact(
        "artifact-one",
        expected_registry_revision=first_revision,
    )
    assert revoked.revoked is True
    assert second_revision == 2
    assert revoked.authority_sha256 != first.authority_sha256
    assert registry.verify_integrity().records == 4  # two adapter pins + artifact history

    with pytest.raises(
        composition.AIEvidenceAnalysisAuthorityConflict,
        match="revision changed",
    ):
        registry.revoke_artifact(
            "artifact-one",
            expected_registry_revision=first_revision,
        )


def test_case_artifact_limit_is_atomic_under_concurrent_enrollment(tmp_path: Path) -> None:
    registry = _build(
        tmp_path,
        config=_config(max_artifacts_per_case=1),
    ).registry
    barrier = threading.Barrier(2)

    def enroll(index: int):
        barrier.wait(timeout=5)
        return registry.enroll_artifact(
            artifact_id=f"artifact-{index}",
            case_ref="case-concurrent",
            media_type=evidence.MEDIA_TEXT,
            content_sha256=_digest(f"artifact-{index}"),
            byte_length=100,
            source_ref=f"source-{index}",
            source_revision=1,
            acquired_at=NOW - 1,
            valid_until=NOW + 100,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(enroll, index) for index in range(2)]
        outcomes: list[object] = []
        for future in futures:
            try:
                outcomes.append(future.result(timeout=10))
            except composition.AIEvidenceAnalysisAuthorityConflict as exc:
                outcomes.append(exc)

    assert sum(isinstance(item, tuple) for item in outcomes) == 1
    assert sum(
        isinstance(item, composition.AIEvidenceAnalysisAuthorityConflict)
        for item in outcomes
    ) == 1
    assert registry.verify_integrity().active_artifacts == 1


def test_expired_artifact_stops_consuming_live_case_capacity(tmp_path: Path) -> None:
    clock = Clock()
    registry = _build(
        tmp_path,
        config=_config(max_artifacts_per_case=1),
        clock=clock,
    ).registry
    registry.enroll_artifact(
        artifact_id="artifact-expiring",
        case_ref="case-live-capacity",
        media_type=evidence.MEDIA_TEXT,
        content_sha256=_digest("expiring"),
        byte_length=100,
        source_ref="source-expiring",
        source_revision=1,
        acquired_at=NOW - 1,
        valid_until=NOW + 10,
    )
    clock.value = NOW + 11

    registry.enroll_artifact(
        artifact_id="artifact-current",
        case_ref="case-live-capacity",
        media_type=evidence.MEDIA_TEXT,
        content_sha256=_digest("current"),
        byte_length=100,
        source_ref="source-current",
        source_revision=1,
        acquired_at=NOW + 1,
        valid_until=NOW + 100,
    )

    report = registry.verify_integrity()
    assert report.active_artifacts == 1
    assert report.live_authorities == 3  # two adapters and the current artifact
    assert report.retained_expired_authorities == 1


def test_registry_history_budget_fails_closed_but_preserves_revocation(
    tmp_path: Path,
) -> None:
    registry = _build(
        tmp_path,
        config=_config(max_authority_records=4),
    ).registry
    for index in range(2):
        registry.enroll_artifact(
            artifact_id=f"artifact-budget-{index}",
            case_ref=f"case-budget-{index}",
            media_type=evidence.MEDIA_TEXT,
            content_sha256=_digest(f"budget-{index}"),
            byte_length=100,
            source_ref=f"source-budget-{index}",
            source_revision=1,
            acquired_at=NOW - 1,
            valid_until=NOW + 100,
        )

    with pytest.raises(
        composition.AIEvidenceAnalysisAuthorityConflict,
        match="history capacity",
    ):
        registry.enroll_artifact(
            artifact_id="artifact-budget-blocked",
            case_ref="case-budget-blocked",
            media_type=evidence.MEDIA_TEXT,
            content_sha256=_digest("budget-blocked"),
            byte_length=100,
            source_ref="source-budget-blocked",
            source_revision=1,
            acquired_at=NOW - 1,
            valid_until=NOW + 100,
        )

    revoked, revision = registry.revoke_artifact(
        "artifact-budget-0",
        expected_registry_revision=1,
    )
    assert revoked.revoked is True
    assert revision == 2
    assert registry.verify_integrity().records == 5


def test_authority_retention_compacts_to_minimized_tombstone_and_rolling_anchor(
    tmp_path: Path,
) -> None:
    clock = Clock()
    retention_seconds = 7_200
    registry = _build(
        tmp_path,
        config=_config(retention_seconds=retention_seconds),
        clock=clock,
    ).registry
    registry.enroll_artifact(
        artifact_id="artifact-retired-sensitive",
        case_ref="case-retired",
        media_type=evidence.MEDIA_TEXT,
        content_sha256=_digest("retired"),
        byte_length=100,
        source_ref="source-retired",
        source_revision=1,
        acquired_at=NOW - 1,
        valid_until=NOW + 10,
    )
    clock.value = NOW + 10 + retention_seconds + 1

    first = registry.compact_expired(limit=10)

    assert first.records_before == 3
    assert first.records_after == 2
    assert first.compacted_authorities == 1
    assert first.compacted_records == 1
    assert first.tombstones_after == 1
    assert first.compaction_anchor_sha256 != "0" * 64
    report = registry.verify_integrity()
    assert report.tombstones == 1
    assert report.compacted_authorities == 1
    assert report.compacted_records == 1
    assert registry.current_registry_revision("artifact", "artifact-retired-sensitive") == 1
    with pytest.raises(
        composition.AIEvidenceAnalysisAuthorityConflict,
        match="retired evidence authority identifier",
    ):
        registry.enroll_artifact(
            artifact_id="artifact-retired-sensitive",
            case_ref="case-retired",
            media_type=evidence.MEDIA_TEXT,
            content_sha256=_digest("replay"),
            byte_length=100,
            source_ref="source-replay",
            source_revision=2,
            acquired_at=clock.value,
            valid_until=clock.value + 100,
            expected_registry_revision=1,
        )
    assert b"artifact-retired-sensitive" not in registry.path.read_bytes()
    with registry._connect() as connection:  # noqa: SLF001 - minimized schema proof
        tombstone = connection.execute(
            "SELECT * FROM ai_evidence_authority_tombstones"
        ).fetchone()
    assert tombstone is not None
    assert "object_key" not in tombstone.keys()
    assert "payload_json" not in tombstone.keys()

    clock.value += retention_seconds + 1
    second = registry.compact_expired(limit=10)

    assert second.compacted_authorities == 0
    assert second.purged_tombstones == 1
    assert second.tombstones_after == 0
    assert second.compaction_anchor_sha256 != first.compaction_anchor_sha256
    assert registry.verify_integrity().purged_tombstones == 1
    assert registry.current_registry_revision("artifact", "artifact-retired-sensitive") == 0


def test_registry_rejects_conclusion_codes_before_enrollment(tmp_path: Path) -> None:
    registry = _build(tmp_path).registry
    criterion = replace(
        _criterion(),
        gap_code="gap.noncompliant",
        criterion_sha256="0" * 64,
    )

    with pytest.raises(
        composition.AIEvidenceAnalysisCompositionError,
        match="cannot encode a legal or compliance conclusion",
    ):
        registry.enroll_criteria(
            criteria_set_id="criteria-conclusion",
            revision=1,
            criteria=(criterion,),
            valid_until=NOW + 100,
        )


def test_real_store_round_trip_reopens_without_raw_content(tmp_path: Path) -> None:
    clock = Clock()
    material = _build(tmp_path, clock=clock)
    raw = b"secret-raw-prefix\nLIGHTWORK_EVIDENCE_FACT:FACT.access"
    artifact_authority, criteria = _enroll_round_trip_authorities(material, raw)

    record = material.store.analyze(
        TENANT,
        artifact=evidence.EvidenceArtifact(
            artifact_id="artifact-one",
            media_type=evidence.MEDIA_TEXT,
            content=raw,
            source_ref="source-vault",
            source_revision=1,
            acquired_at=NOW - 10,
        ),
        expected_artifact_authority_sha256=artifact_authority.authority_sha256,
        criteria_set_id="criteria-one",
        expected_criteria_revision=criteria.revision,
        expected_criteria_authority_sha256=criteria.authority_sha256,
        submitter_ref="submitter-one",
        valid_until=NOW + 1_000,
        retained_until=NOW + 2_000,
        idempotency_key="analyze-one",
    )
    assert record.summary.evidence_supported == 1
    assert record.status == "pending_review"

    reviewed = material.store.review(
        TENANT,
        record.analysis_id,
        reviewer_ref="reviewer-two",
        decision="approve",
        expected_revision=1,
        idempotency_key="review-one",
    )
    assert reviewed.status == "review_approved"
    assert material.store.get_released(TENANT, record.analysis_id) == reviewed
    assert material.registry.verify_integrity().records == 5
    assert raw not in material.store.path.read_bytes()
    assert raw not in material.registry.path.read_bytes()
    assert b"submitter-one" not in material.store.path.read_bytes()
    assert b"reviewer-two" not in material.store.path.read_bytes()
    assert b"reviewer-two" not in material.registry.path.read_bytes()
    for persisted in (path for path in tmp_path.rglob("*") if path.is_file()):
        contents = persisted.read_bytes()
        assert raw not in contents, persisted
        assert b"submitter-one" not in contents, persisted
        assert b"reviewer-two" not in contents, persisted

    reopened = _build(tmp_path, clock=clock, bootstrap=False)
    assert reopened.store.get(TENANT, record.analysis_id) == reviewed
    report = reopened.store.verify_integrity(TENANT)
    assert report.analyses == 1
    assert reopened.registry.verify_integrity().records == 5


def test_adapter_revocation_blocks_restart_and_is_not_resurrected(tmp_path: Path) -> None:
    material = _build(tmp_path)
    authority = material.extraction_authority
    key = material.registry._adapter_key(  # noqa: SLF001 - exact registry key assertion
        authority.stage,
        authority.adapter_id,
        authority.revision,
    )
    revision = material.registry.current_registry_revision("adapter", key)
    revoked, next_revision = material.registry.revoke_adapter(
        stage=authority.stage,
        adapter_id=authority.adapter_id,
        revision=authority.revision,
        expected_registry_revision=revision,
    )
    assert revoked.revoked is True
    assert next_revision == 2

    with pytest.raises(composition.AIEvidenceAnalysisCompositionError, match="revoked"):
        _build(tmp_path, bootstrap=True)
    with pytest.raises(composition.AIEvidenceAnalysisCompositionError, match="changed"):
        _build(tmp_path, bootstrap=False)


def test_local_adapter_rotation_is_explicit_and_cannot_undo_revocation(
    tmp_path: Path,
) -> None:
    clock = Clock()
    material = _build(tmp_path, clock=clock)
    current = material.extraction_authority
    key = material.registry._adapter_key(  # noqa: SLF001 - exact registry key assertion
        current.stage,
        current.adapter_id,
        current.revision,
    )
    clock.value += 100

    renewed, registry_revision = composition.rotate_local_adapter_authority(
        material.registry,
        stage=current.stage,
        adapter_id=current.adapter_id,
        revision=current.revision,
        expected_registry_revision=1,
        clock=clock,
    )

    assert registry_revision == 2
    assert renewed.valid_until > current.valid_until
    assert material.registry.current_registry_revision("adapter", key) == 2
    assert _build(tmp_path, clock=clock, bootstrap=False).extraction_authority == renewed

    material.registry.revoke_adapter(
        stage=current.stage,
        adapter_id=current.adapter_id,
        revision=current.revision,
        expected_registry_revision=2,
    )
    with pytest.raises(
        composition.AIEvidenceAnalysisCompositionError,
        match="cannot be renewed",
    ):
        composition.rotate_local_adapter_authority(
            material.registry,
            stage=current.stage,
            adapter_id=current.adapter_id,
            revision=current.revision,
            expected_registry_revision=3,
            clock=clock,
        )


def _adapter_as_enrolled_by(
    current: evidence.EvidenceAdapterAuthority,
    *,
    revision: int,
    implementation_sha256: str,
) -> evidence.EvidenceAdapterAuthority:
    raw = replace(
        current,
        revision=revision,
        implementation_sha256=implementation_sha256,
        authority_sha256="0" * 64,
    )
    return replace(raw, authority_sha256=evidence.adapter_authority_sha256(raw))


def _registry_at(tmp_path: Path, clock) -> composition.EvidenceAuthorityRegistry:
    return composition.EvidenceAuthorityRegistry(
        tmp_path / "authorities.sqlite3",
        tenant_id=TENANT,
        settings=composition.ai_evidence_analysis_settings(_config()),
        clock=clock,
    )


def test_registry_enrolled_before_the_upgrade_refuses_reads_until_enrolled_again(
    tmp_path: Path,
) -> None:
    # The adapter revision is part of the registry key, so a registry enrolled at
    # revision 3 has no revision-4 enrollment: reads refuse, and bootstrap enrolls.
    clock = Clock()
    current = _build(tmp_path / "source", clock=clock).extraction_authority
    enrolled_at_three = _adapter_as_enrolled_by(
        current,
        revision=3,
        implementation_sha256=_digest("implementation-before-upgrade"),
    )
    registry = _registry_at(tmp_path, clock)
    registry.enroll_adapter(enrolled_at_three)

    with pytest.raises(
        composition.AIEvidenceAnalysisCompositionError,
        match=(
            "not enrolled for this revision; after an upgrade the local evidence adapter "
            "must be enrolled again; .*first use.*POST /api/v1/ai-evidence-analysis/"
            "authorities/bootstrap"
        ),
    ):
        _build(tmp_path, clock=clock, bootstrap=False)
    assert registry.resolve_adapter(TENANT, "extraction", "local-bounded-extraction", 3) == (
        enrolled_at_three
    )

    enrolled = _build(tmp_path, clock=clock, bootstrap=True)
    assert enrolled.extraction_authority.revision == 4
    # The criteria-match analysis adapter has its own revision and is unchanged.
    assert enrolled.analysis_authority.revision == 1
    reopened = _build(tmp_path, clock=clock, bootstrap=False)
    assert reopened.extraction_authority == enrolled.extraction_authority
    assert reopened.analysis_authority == enrolled.analysis_authority


def test_admin_bootstrap_enrolls_the_local_adapter_again_at_revision_four(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = time.time
    current = _build(tmp_path / "source", clock=clock).extraction_authority
    registry = _registry_at(tmp_path, clock)
    registry.enroll_adapter(
        _adapter_as_enrolled_by(
            current,
            revision=3,
            implementation_sha256=_digest("implementation-before-upgrade"),
        )
    )
    permission_calls: list[str] = []
    monkeypatch.setattr(authority_api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(
        authority_api,
        "require_global_permission",
        lambda _request, permission: permission_calls.append(permission),
    )
    app = FastAPI()
    app.state.ai_evidence_analysis_authority_registry_factory = lambda _tenant: registry
    app.include_router(
        authority_api.create_ai_evidence_analysis_authority_router(),
        prefix="/api/v1",
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    response = client.post("/api/v1/ai-evidence-analysis/authorities/bootstrap")

    assert response.status_code == 200, response.text
    assert permission_calls == ["admin"]
    assert [item["revision"] for item in response.json()["adapters"]] == [4, 1]
    reopened = _build(tmp_path, clock=clock, bootstrap=False)
    assert reopened.extraction_authority.revision == 4


def test_analysis_recorded_before_the_upgrade_is_refused_for_review_and_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()
    raw = b"LIGHTWORK_EVIDENCE_FACT:FACT.access"
    monkeypatch.setattr(local_parsers, "_ADAPTER_REVISION", 3)
    before = _build(tmp_path, clock=clock)
    assert before.extraction_authority.revision == 3
    artifact_authority, criteria = _enroll_round_trip_authorities(before, raw)
    artifact = evidence.EvidenceArtifact(
        artifact_id="artifact-one",
        media_type=evidence.MEDIA_TEXT,
        content=raw,
        source_ref="source-vault",
        source_revision=1,
        acquired_at=NOW - 10,
    )

    def analyze(key: str):
        return before.store.analyze(
            TENANT,
            artifact=artifact,
            expected_artifact_authority_sha256=artifact_authority.authority_sha256,
            criteria_set_id="criteria-one",
            expected_criteria_revision=criteria.revision,
            expected_criteria_authority_sha256=criteria.authority_sha256,
            submitter_ref="submitter-one",
            valid_until=NOW + 1_000,
            retained_until=NOW + 2_000,
            idempotency_key=key,
        )

    pending = analyze("analyze-pending")
    released = analyze("analyze-released")
    before.store.review(
        TENANT,
        released.analysis_id,
        reviewer_ref="reviewer-two",
        decision="approve",
        expected_revision=1,
        idempotency_key="approve-before-upgrade",
    )
    monkeypatch.undo()

    upgraded = _build(tmp_path, clock=clock)
    assert upgraded.extraction_authority.revision == 4
    with pytest.raises(evidence.EvidenceAnalysisConflict, match="adapter authority changed"):
        upgraded.store.review(
            TENANT,
            pending.analysis_id,
            reviewer_ref="reviewer-two",
            decision="approve",
            expected_revision=1,
            idempotency_key="review-after-upgrade",
        )
    with pytest.raises(evidence.EvidenceAnalysisConflict, match="adapter authority changed"):
        upgraded.store.get_released(TENANT, released.analysis_id)
    assert upgraded.store.verify_integrity(TENANT).analyses == 2


def test_changed_local_adapter_implementation_is_refused_and_not_overwritten(
    tmp_path: Path,
) -> None:
    clock = Clock()
    source = _build(tmp_path / "source", clock=clock)
    changed = _adapter_as_enrolled_by(
        source.extraction_authority,
        revision=source.extraction_authority.revision,
        implementation_sha256=_digest("another-implementation"),
    )
    registry = _registry_at(tmp_path, clock)
    registry.enroll_adapter(changed)
    registry.enroll_adapter(source.analysis_authority)
    key = registry._adapter_key(  # noqa: SLF001 - exact registry key assertion
        changed.stage,
        changed.adapter_id,
        changed.revision,
    )

    for bootstrap in (True, False):
        with pytest.raises(
            composition.AIEvidenceAnalysisCompositionError,
            match="changed, expired, or was revoked",
        ):
            _build(tmp_path, clock=clock, bootstrap=bootstrap)
    assert registry.current_registry_revision("adapter", key) == 1
    assert (
        registry.resolve_adapter(TENANT, changed.stage, changed.adapter_id, changed.revision)
        == changed
    )


def test_authority_lifetimes_are_bounded(tmp_path: Path) -> None:
    registry = _build(tmp_path).registry

    with pytest.raises(
        composition.AIEvidenceAnalysisCompositionError,
        match="lifetime bound",
    ):
        registry.enroll_artifact(
            artifact_id="artifact-long-lived",
            case_ref="case-one",
            media_type=evidence.MEDIA_TEXT,
            content_sha256=_digest("long-lived"),
            byte_length=100,
            source_ref="source-one",
            source_revision=1,
            acquired_at=NOW - 1,
            valid_until=NOW + (367 * 24 * 60 * 60),
        )


def test_store_rechecks_live_configuration_gate(tmp_path: Path) -> None:
    admitted = True

    def gate() -> None:
        if not admitted:
            raise composition.AIEvidenceAnalysisCompositionError("configuration changed")

    material = composition.build_ai_evidence_analysis_composition(
        tenant_id=TENANT,
        config=_config(),
        registry_path=tmp_path / "authorities.sqlite3",
        analysis_path=tmp_path / "analyses.sqlite3",
        clock=Clock(),
        config_gate=gate,
    )
    admitted = False

    with pytest.raises(
        composition.AIEvidenceAnalysisCompositionError,
        match="configuration changed",
    ):
        material.store.verify_integrity(TENANT)


def test_retention_purge_verifies_and_removes_due_analysis(tmp_path: Path) -> None:
    clock = Clock()
    material = _build(tmp_path, clock=clock)
    raw = b"LIGHTWORK_EVIDENCE_FACT:FACT.access"
    artifact_authority, criteria = _enroll_round_trip_authorities(material, raw)
    record = material.store.analyze(
        TENANT,
        artifact=evidence.EvidenceArtifact(
            artifact_id="artifact-one",
            media_type=evidence.MEDIA_TEXT,
            content=raw,
            source_ref="source-vault",
            source_revision=1,
            acquired_at=NOW - 10,
        ),
        expected_artifact_authority_sha256=artifact_authority.authority_sha256,
        criteria_set_id="criteria-one",
        expected_criteria_revision=criteria.revision,
        expected_criteria_authority_sha256=criteria.authority_sha256,
        submitter_ref="submitter-one",
        valid_until=NOW + 30,
        retained_until=NOW + 60,
        idempotency_key="retention-one",
    )
    assert material.store.verify_integrity(TENANT).analyses == 1

    clock.value = NOW + 61
    purged = material.store.purge_expired(TENANT)

    assert purged.analysis_ids == (record.analysis_id,)
    assert purged.operations == 1
    assert material.store.verify_integrity(TENANT).analyses == 0


def test_composed_maintenance_covers_core_and_authority_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()
    retention_seconds = 7_200
    material = _build(
        tmp_path,
        config=_config(retention_seconds=retention_seconds),
        clock=clock,
    )
    material.registry.enroll_artifact(
        artifact_id="artifact-maintenance",
        case_ref="case-maintenance",
        media_type=evidence.MEDIA_TEXT,
        content_sha256=_digest("maintenance"),
        byte_length=100,
        source_ref="source-maintenance",
        source_revision=1,
        acquired_at=NOW - 1,
        valid_until=NOW + 10,
    )
    clock.value = NOW + 10 + retention_seconds + 1
    monkeypatch.setattr(
        composition,
        "_installed_composition",
        lambda _tenant, *, bootstrap_local_adapters: material,
    )

    result = composition.run_ai_evidence_analysis_maintenance(TENANT, limit=10)

    assert result.schema == "lightwork.ai-evidence.maintenance-result.v2"
    assert result.registry_records_before == 3
    assert result.registry_records == 2
    assert result.compacted_authorities == 1
    assert result.compacted_authority_records == 1
    assert result.authority_tombstones == 1
    assert result.purged_analyses == 0
    assert result.integrity_verified is True


def test_byte_bounded_adapter_and_transport_store_limit(tmp_path: Path) -> None:
    adapter = composition.ByteBoundedLocalExtractionAdapter(maximum_bytes=1_024)
    assert adapter._bounded("a" * 1_024) == "a" * 1_024  # noqa: SLF001
    with pytest.raises(evidence.EvidenceAnalysisValidationError, match="byte bound"):
        adapter._bounded("é" * 600)  # noqa: SLF001

    material = _build(tmp_path, config=_config(max_artifact_bytes=1_024))
    oversized = evidence.EvidenceArtifact(
        artifact_id="artifact-unenrolled",
        media_type=evidence.MEDIA_TEXT,
        content=b"x" * 1_025,
        source_ref="source-one",
        source_revision=1,
        acquired_at=NOW - 1,
    )
    with pytest.raises(evidence.EvidenceAnalysisValidationError, match="tenant byte limit"):
        material.store.analyze(
            TENANT,
            artifact=oversized,
            expected_artifact_authority_sha256="0" * 64,
            criteria_set_id="criteria-one",
            expected_criteria_revision=1,
            expected_criteria_authority_sha256="0" * 64,
            submitter_ref="submitter-one",
            valid_until=NOW + 100,
            retained_until=NOW + 200,
            idempotency_key="oversized",
        )


def test_install_is_lazy_idempotent_and_preserves_deployment_overrides() -> None:
    app = FastAPI()
    custom = lambda *_args, **_kwargs: "custom"  # noqa: E731
    app.state.ai_evidence_analysis_store_factory = custom

    composition.install_ai_evidence_analysis_composition(app)
    composition.install_ai_evidence_analysis_composition(app)

    assert app.state.ai_evidence_analysis_store_factory is custom
    assert callable(app.state.ai_evidence_analysis_enabled_probe)
    assert callable(app.state.ai_evidence_analysis_lifetime_resolver)
    assert callable(app.state.ai_evidence_analysis_readiness_probe)
    assert callable(app.state.ai_evidence_analysis_status_settings_resolver)
    assert callable(app.state.ai_evidence_analysis_artifact_limit_resolver)
    assert callable(app.state.ai_evidence_analysis_authority_registry_factory)
    assert callable(app.state.ai_evidence_analysis_maintenance_runner)
    assert app.state.ai_evidence_analysis_composition_installed is True


def test_admin_router_is_global_permission_bound_and_metadata_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()
    material = _build(tmp_path, clock=clock)
    permission_calls: list[str] = []
    monkeypatch.setattr(authority_api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(
        authority_api,
        "require_global_permission",
        lambda _request, permission: permission_calls.append(permission),
    )
    app = FastAPI()
    app.state.ai_evidence_analysis_authority_registry_factory = (
        lambda _tenant: material.registry
    )

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(sub="admin")
        return await call_next(request)

    app.include_router(
        authority_api.create_ai_evidence_analysis_authority_router(),
        prefix="/api/v1",
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    body = {
        "case_ref": "case-api",
        "media_type": "text",
        "content_sha256": _digest("metadata-only"),
        "byte_length": 128,
        "source_ref": "source-api",
        "source_revision": 1,
        "acquired_at": NOW - 1,
        "valid_until": NOW + 100,
        "expected_registry_revision": 0,
    }
    response = client.put(
        "/api/v1/ai-evidence-analysis/authorities/artifacts/artifact-api",
        json=body,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert permission_calls == ["admin"]
    assert payload["raw_artifact_content_persisted"] is False
    assert payload["extracted_text_persisted"] is False
    assert payload["external_acceptance_verified"] is False
    assert "content" not in payload["authority"]
    assert "text" not in payload["authority"]

    clock.value += 100
    rotated = client.post(
        "/api/v1/ai-evidence-analysis/authorities/adapters/"
        f"{material.extraction_authority.stage}/"
        f"{material.extraction_authority.adapter_id}/"
        f"{material.extraction_authority.revision}/rotate",
        json={"expected_registry_revision": 1},
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["registry_revision"] == 2
    assert permission_calls == ["admin", "admin"]

    extra = dict(body, raw_artifact="forbidden")
    rejected = client.put(
        "/api/v1/ai-evidence-analysis/authorities/artifacts/artifact-extra",
        json=extra,
    )
    assert rejected.status_code == 422
    assert material.registry.current_registry_revision("artifact", "artifact-extra") == 0


def test_registry_lists_only_usable_authorities_for_pickers(tmp_path: Path) -> None:
    clock = Clock()
    material = _build(tmp_path, clock=clock)
    artifact, criteria = _enroll_round_trip_authorities(material, b"picker evidence")
    artifacts = material.registry.list_usable_artifacts()
    assert [item["artifact_id"] for item in artifacts] == ["artifact-one"]
    assert artifacts[0]["authority_sha256"] == artifact.authority_sha256
    assert artifacts[0]["case_ref"] == "case-one"
    assert artifacts[0]["registry_revision"] == 1
    listed = material.registry.list_usable_criteria()
    assert listed == [
        {
            "criteria_set_id": "criteria-one",
            "revision": 1,
            "criterion_ids": ["criterion-access"],
            "valid_until": criteria.valid_until,
            "authority_sha256": criteria.authority_sha256,
            "registry_revision": 1,
        }
    ]
    material.registry.revoke_artifact("artifact-one", expected_registry_revision=1)
    assert material.registry.list_usable_artifacts() == []
    clock.value += 7_200
    assert material.registry.list_usable_criteria() == []
    other = _build(tmp_path / "other", clock=clock)
    assert other.registry.list_usable_artifacts() == []


def test_picker_lists_use_tenant_view_permission_and_the_workspace_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = _build(tmp_path)
    _enroll_round_trip_authorities(material, b"picker api evidence")
    permissions: list[str] = []
    monkeypatch.setattr(authority_api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(
        authority_api, "require_permission", lambda _request, value: permissions.append(value)
    )
    monkeypatch.setattr(
        authority_api,
        "require_global_permission",
        lambda _request, value: permissions.append("global:" + value),
    )
    requested: list[str] = []
    app = FastAPI()

    def factory(tenant: str):
        requested.append(tenant)
        return material.registry

    app.state.ai_evidence_analysis_authority_registry_factory = factory
    app.include_router(
        authority_api.create_ai_evidence_analysis_authority_router(), prefix="/api/v1"
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    artifacts = client.get("/api/v1/ai-evidence-analysis/authorities/artifacts")
    criteria = client.get("/api/v1/ai-evidence-analysis/authorities/criteria")
    assert artifacts.status_code == 200 and criteria.status_code == 200
    assert artifacts.json()["items"][0]["artifact_id"] == "artifact-one"
    assert criteria.json()["items"][0]["criteria_set_id"] == "criteria-one"
    assert permissions == ["view", "view"]
    assert requested == [TENANT, TENANT]
    assert "content" not in artifacts.json()["items"][0]


def test_upload_registration_computes_the_fingerprint_on_the_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = _build(tmp_path)
    permissions: list[str] = []
    monkeypatch.setattr(authority_api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(
        authority_api,
        "require_global_permission",
        lambda _request, value: permissions.append(value),
    )
    app = FastAPI()
    app.state.ai_evidence_analysis_authority_registry_factory = lambda _tenant: material.registry
    app.include_router(
        authority_api.create_ai_evidence_analysis_authority_router(), prefix="/api/v1"
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    raw = b"supplier contract text"
    response = client.post(
        "/api/v1/ai-evidence-analysis/authorities/artifacts/register",
        params={"name": "Supplier Contract.txt", "matter": "Supplier review 2026",
                "received_at": NOW - 86_400, "valid_days": 30},
        content=raw,
        headers={"Content-Type": evidence.MEDIA_TEXT},
    )
    assert response.status_code == 200, response.text
    assert permissions == ["admin"]
    authority = response.json()["authority"]
    digest = hashlib.sha256(raw).hexdigest()
    assert authority["content_sha256"] == digest
    assert authority["byte_length"] == len(raw)
    assert authority["artifact_id"] == f"supplier-contract-txt.{digest[:8]}"
    assert raw.decode() not in response.text
    listed = material.registry.list_usable_artifacts()
    assert listed[0]["case_ref"] == "supplier-review-2026"
    unsupported = client.post(
        "/api/v1/ai-evidence-analysis/authorities/artifacts/register",
        params={"name": "x", "matter": "y", "received_at": NOW},
        content=b"<html>",
        headers={"Content-Type": "text/html"},
    )
    assert unsupported.status_code == 415


def _assert_closed(connections):
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_composition_owned_connections_are_closed_when_their_calls_return(tmp_path, monkeypatch):
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: any connection left open by a call stays open.
    opened = []
    real_connect = sqlite3.connect
    fail_pragma = {"on": True}

    class _PragmaFailsMixin:
        def execute(self, sql, *args):
            if sql == "PRAGMA foreign_keys=ON" and fail_pragma["on"]:
                raise sqlite3.OperationalError("pragma failed")
            return super().execute(sql, *args)

    def recording_connect(*args, **kwargs):
        # Only connections opened by this module's helpers are under test; the
        # analysis store in maverick.ai_evidence_analysis opens its own, and every
        # other call keeps its arguments unchanged, including a caller's factory.
        own = sys._getframe(1).f_code.co_filename == composition.__file__
        if not own:
            return real_connect(*args, **kwargs)
        base = kwargs.pop("factory", sqlite3.Connection)
        pragma_fails = type("_PragmaFails", (_PragmaFailsMixin, base), {})
        connection = real_connect(*args, factory=pragma_fails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(composition.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        with pytest.raises(sqlite3.OperationalError):
            _build(tmp_path)
        fail_pragma["on"] = False
        before = len(opened)
        comp = _build(tmp_path)
        assert len(opened) > before, "__init__"
        _assert_closed(opened[before:])
        calls = [
            ("list_usable_artifacts", comp.registry.list_usable_artifacts),
            ("list_usable_criteria", comp.registry.list_usable_criteria),
            ("verify_integrity", comp.registry.verify_integrity),
            ("current_registry_revision", lambda: comp.registry.current_registry_revision("artifact", "missing")),
            # A missing authority reads its retirement tombstone, then raises.
            (
                "_current_payload",
                lambda: comp.registry._current_payload("artifact", "missing-artifact"),
            ),
            ("compact_expired", lambda: comp.registry.compact_expired(limit=10)),
        ]
        for name, call in calls:
            before = len(opened)
            with contextlib.suppress(composition.AIEvidenceAnalysisCompositionError):
                call()
            assert len(opened) > before, name
            _assert_closed(opened[before:])
    finally:
        gc.enable()
    _assert_closed(opened)
