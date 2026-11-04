from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick import no_code_grc_studio as studio

NOW = 2_000_000_000.0
KEY = b"k" * 32


def blueprint(studio_id: str = "enterprise-grc") -> dict[str, object]:
    return {
        "schema": studio.BLUEPRINT_SCHEMA,
        "studio_id": studio_id,
        "name_ref": "enterprise-grc-name",
        "description_ref": "enterprise-grc-description",
        "objects": [
            {
                "object_id": "risk-record",
                "kind": "risk",
                "label_ref": "risk-label",
                "description_ref": "risk-description",
                "fields": [
                    {
                        "field_id": "severity",
                        "label_ref": "severity-label",
                        "field_type": "single_choice",
                        "required": True,
                        "sensitivity": "internal",
                        "options": ["low", "medium", "high"],
                        "reference_kind": None,
                        "default": "medium",
                    },
                    {
                        "field_id": "evidence",
                        "label_ref": "evidence-label",
                        "field_type": "evidence_ref",
                        "required": False,
                        "sensitivity": "confidential",
                        "options": [],
                        "reference_kind": "control-evidence",
                        "default": None,
                    },
                ],
            }
        ],
        "forms": [
            {
                "form_id": "risk-intake",
                "object_id": "risk-record",
                "title_ref": "risk-intake-title",
                "sections": [
                    {
                        "section_id": "risk-core",
                        "label_ref": "risk-core-label",
                        "field_ids": ["severity", "evidence"],
                    }
                ],
            }
        ],
        "rules": [
            {
                "rule_id": "high-risk-evidence",
                "object_id": "risk-record",
                "when": {
                    "mode": "all",
                    "conditions": [{"field_id": "severity", "operator": "equals", "value": "high"}],
                },
                "then": [
                    {
                        "action_id": "require-evidence",
                        "action_type": "set_required",
                        "target_field_id": "evidence",
                        "value": True,
                    }
                ],
            }
        ],
        "collector_bindings": [
            {
                "binding_id": "cloud-evidence",
                "collector_id": "cloud-config",
                "collector_version": 3,
                "collector_integrity_sha256": "a" * 64,
                "object_id": "risk-record",
                "field_mappings": [
                    {
                        "source_path": ["finding", "severity"],
                        "target_field_id": "severity",
                        "mode": "replace",
                    }
                ],
                "control_refs": ["iso-a.5.1"],
            }
        ],
        "report_views": [
            {
                "view_id": "risk-register",
                "object_id": "risk-record",
                "title_ref": "risk-register-title",
                "columns": ["severity", "evidence"],
                "filters": [{"field_id": "severity", "operator": "is_set", "value": None}],
                "group_by": ["severity"],
                "sort": [{"field_id": "severity", "direction": "descending"}],
            }
        ],
    }


def make_store(
    tmp_path: Path,
    actor: dict[str, str],
    *,
    tenant: str = "tenant-a",
    now: dict[str, float] | None = None,
) -> studio.GRCStudioStore:
    clock = now or {"value": NOW}
    return studio.GRCStudioStore(
        tmp_path / "grc.sqlite3",
        tenant_id=tenant,
        integrity_key=KEY,
        principal_resolver=lambda: actor["value"],
        maintenance_authorizer=lambda: True,
        config_gate=lambda: None,
        clock=lambda: clock["value"],
        max_studios=50,
        retention_seconds=86_400,
        recovery_directory=tmp_path / "recovery",
    )


def approve_release(
    store: studio.GRCStudioStore,
    actor: dict[str, str],
    version: studio.StudioVersion,
    prefix: str,
) -> studio.StudioVersion:
    version = store.submit_for_review(
        "tenant-a",
        version.studio_id,
        version.version,
        expected_revision=version.revision,
        expected_integrity_sha256=version.integrity_sha256,
        operation_id=f"{prefix}-submit",
    )
    actor["value"] = "reviewer"
    version = store.review(
        "tenant-a",
        version.studio_id,
        version.version,
        accepted=True,
        rationale_ref="review-passed",
        expected_revision=version.revision,
        expected_integrity_sha256=version.integrity_sha256,
        operation_id=f"{prefix}-review",
    )
    actor["value"] = "approver"
    return store.approve(
        "tenant-a",
        version.studio_id,
        version.version,
        approval_ref="grc-board",
        expected_revision=version.revision,
        expected_integrity_sha256=version.integrity_sha256,
        operation_id=f"{prefix}-approve",
    )


def test_closed_dsl_rejects_code_urls_unknown_fields_and_broken_references() -> None:
    valid = studio.validate_blueprint(blueprint())
    assert valid["studio_id"] == "enterprise-grc"

    unknown = blueprint()
    unknown["eval"] = "__import__"
    with pytest.raises(studio.GRCStudioValidationError, match="closed"):
        studio.validate_blueprint(unknown)

    url = blueprint()
    url["name_ref"] = "https://attacker.invalid"
    with pytest.raises(studio.GRCStudioValidationError, match="opaque"):
        studio.validate_blueprint(url)

    uri = blueprint()
    uri["name_ref"] = "urn:attacker"
    with pytest.raises(studio.GRCStudioValidationError, match="opaque"):
        studio.validate_blueprint(uri)

    expression = blueprint()
    expression["rules"][0]["expression"] = "process.exit()"
    with pytest.raises(studio.GRCStudioValidationError, match="closed"):
        studio.validate_blueprint(expression)

    broken = blueprint()
    broken["forms"][0]["sections"][0]["field_ids"] = ["missing"]
    with pytest.raises(studio.GRCStudioValidationError, match="reference"):
        studio.validate_blueprint(broken)

    incompatible = blueprint()
    incompatible["rules"][0]["when"]["conditions"][0]["operator"] = "greater_than"
    with pytest.raises(studio.GRCStudioValidationError, match="ordering"):
        studio.validate_blueprint(incompatible)

    malformed_filter = blueprint()
    malformed_filter["report_views"][0]["filters"][0]["value"] = "high"
    with pytest.raises(studio.GRCStudioValidationError, match="is_set"):
        studio.validate_blueprint(malformed_filter)


def test_lifecycle_requires_distinct_review_and_approval_and_exact_cas(tmp_path: Path) -> None:
    actor = {"value": "author"}
    store = make_store(tmp_path, actor)
    version = store.create_version(
        "tenant-a",
        "enterprise-grc",
        blueprint=blueprint(),
        expected_latest_version=0,
        operation_id="create-v1",
    )
    assert version.state == "draft"
    assert (
        store.create_version(
            "tenant-a",
            "enterprise-grc",
            blueprint=blueprint(),
            expected_latest_version=0,
            operation_id="create-v1",
        )
        == version
    )
    with pytest.raises(studio.GRCStudioConflict):
        store.replace_draft(
            "tenant-a",
            "enterprise-grc",
            1,
            blueprint=blueprint(),
            expected_revision=999,
            expected_integrity_sha256=version.integrity_sha256,
            operation_id="bad-cas",
        )
    version = store.submit_for_review(
        "tenant-a",
        "enterprise-grc",
        1,
        expected_revision=version.revision,
        expected_integrity_sha256=version.integrity_sha256,
        operation_id="submit-v1",
    )
    with pytest.raises(studio.GRCStudioPermissionDenied, match="distinct"):
        store.review(
            "tenant-a",
            "enterprise-grc",
            1,
            accepted=True,
            rationale_ref="same-author",
            expected_revision=version.revision,
            expected_integrity_sha256=version.integrity_sha256,
            operation_id="review-v1-author",
        )
    actor["value"] = "reviewer"
    version = store.review(
        "tenant-a",
        "enterprise-grc",
        1,
        accepted=True,
        rationale_ref="review-ok",
        expected_revision=version.revision,
        expected_integrity_sha256=version.integrity_sha256,
        operation_id="review-v1",
    )
    with pytest.raises(studio.GRCStudioPermissionDenied, match="reviewer"):
        store.approve(
            "tenant-a",
            "enterprise-grc",
            1,
            approval_ref="reviewer-self-approval",
            expected_revision=version.revision,
            expected_integrity_sha256=version.integrity_sha256,
            operation_id="approve-v1-reviewer",
        )
    actor["value"] = "author"
    with pytest.raises(studio.GRCStudioPermissionDenied, match="distinct"):
        store.approve(
            "tenant-a",
            "enterprise-grc",
            1,
            approval_ref="author-self-approval",
            expected_revision=version.revision,
            expected_integrity_sha256=version.integrity_sha256,
            operation_id="approve-v1-author",
        )
    actor["value"] = "approver"
    version = store.approve(
        "tenant-a",
        "enterprise-grc",
        1,
        approval_ref="board-approved",
        expected_revision=version.revision,
        expected_integrity_sha256=version.integrity_sha256,
        operation_id="approve-v1",
    )
    published = store.publish(
        "tenant-a",
        "enterprise-grc",
        1,
        expected_revision=version.revision,
        expected_integrity_sha256=version.integrity_sha256,
        expected_active_version=0,
        expected_active_blueprint_sha256=None,
        expected_pointer_revision=0,
        operation_id="publish-v1",
    )
    pointer, active = store.get_active("tenant-a", "enterprise-grc")
    assert published.state == active.state == "published"
    assert pointer.active_version == 1
    assert store.verify_integrity("tenant-a")["verified"] is True


def test_version_publish_and_rollback_reactivate_only_exact_release(tmp_path: Path) -> None:
    actor = {"value": "author"}
    store = make_store(tmp_path, actor)
    first = approve_release(
        store,
        actor,
        store.create_version(
            "tenant-a",
            "enterprise-grc",
            blueprint=blueprint(),
            expected_latest_version=0,
            operation_id="create-first",
        ),
        "first",
    )
    first = store.publish(
        "tenant-a",
        "enterprise-grc",
        1,
        expected_revision=first.revision,
        expected_integrity_sha256=first.integrity_sha256,
        expected_active_version=0,
        expected_active_blueprint_sha256=None,
        expected_pointer_revision=0,
        operation_id="publish-first",
    )
    actor["value"] = "author"
    changed = blueprint()
    changed["name_ref"] = "enterprise-grc-name-v2"
    second = approve_release(
        store,
        actor,
        store.create_version(
            "tenant-a",
            "enterprise-grc",
            blueprint=changed,
            expected_latest_version=1,
            operation_id="create-second",
        ),
        "second",
    )
    pointer, _ = store.get_active("tenant-a", "enterprise-grc")
    second = store.publish(
        "tenant-a",
        "enterprise-grc",
        2,
        expected_revision=second.revision,
        expected_integrity_sha256=second.integrity_sha256,
        expected_active_version=pointer.active_version,
        expected_active_blueprint_sha256=pointer.active_blueprint_sha256,
        expected_pointer_revision=pointer.revision,
        operation_id="publish-second",
    )
    pointer, _ = store.get_active("tenant-a", "enterprise-grc")
    prior = store.get_version("tenant-a", "enterprise-grc", 1)
    rolled = store.rollback(
        "tenant-a",
        "enterprise-grc",
        target_version=1,
        expected_target_blueprint_sha256=prior.blueprint_sha256,
        expected_active_version=2,
        expected_active_blueprint_sha256=second.blueprint_sha256,
        expected_pointer_revision=pointer.revision,
        rationale_ref="production-regression",
        operation_id="rollback-first",
    )
    assert rolled.version == 1
    assert store.get_version("tenant-a", "enterprise-grc", 2).state == "superseded"


def test_tenant_isolation_export_import_and_projection_authority(tmp_path: Path) -> None:
    actor = {"value": "author"}
    store = make_store(tmp_path, actor)
    selected = approve_release(
        store,
        actor,
        store.create_version(
            "tenant-a",
            "enterprise-grc",
            blueprint=blueprint(),
            expected_latest_version=0,
            operation_id="create-for-projection",
        ),
        "projection",
    )
    selected = store.publish(
        "tenant-a",
        "enterprise-grc",
        1,
        expected_revision=selected.revision,
        expected_integrity_sha256=selected.integrity_sha256,
        expected_active_version=0,
        expected_active_blueprint_sha256=None,
        expected_pointer_revision=0,
        operation_id="publish-for-projection",
    )
    exported = store.export_version("tenant-a", "enterprise-grc", 1, operation_id="export-v1")
    with pytest.raises(studio.GRCStudioNotFound):
        store.get_version("tenant-b", "enterprise-grc", 1)

    second_actor = {"value": "importer"}
    second = make_store(tmp_path / "second", second_actor)
    # Same tenant + same deployment custody key can import; a changed byte cannot.
    imported = second.import_version(
        "tenant-a", exported, expected_latest_version=0, operation_id="import-v1"
    )
    assert imported.state == "draft"
    tampered = copy.deepcopy(exported)
    tampered["blueprint"]["name_ref"] = "tampered"
    with pytest.raises(studio.GRCStudioIntegrityError):
        second.import_version(
            "tenant-a", tampered, expected_latest_version=1, operation_id="tampered"
        )

    authority = studio.issue_runtime_target_authority(
        tenant_id="tenant-a",
        target_kind="questionnaire",
        target_id="scope-questionnaire",
        target_revision=4,
        target_integrity_sha256="b" * 64,
        allowed_blueprint_sha256=selected.blueprint_sha256,
        valid_until=NOW + 100,
    )
    projection = store.preview_projection(
        "tenant-a",
        "enterprise-grc",
        projection_kind="questionnaire",
        definition_id="risk-intake",
        target_authority=authority,
        expected_active_version=1,
        expected_blueprint_sha256=selected.blueprint_sha256,
    )
    assert projection["payload"]["definition"]["form_id"] == "risk-intake"
    stale = studio.issue_runtime_target_authority(
        tenant_id="tenant-a",
        target_kind="questionnaire",
        target_id="scope-questionnaire",
        target_revision=4,
        target_integrity_sha256="b" * 64,
        allowed_blueprint_sha256="c" * 64,
        valid_until=NOW + 100,
    )
    with pytest.raises(studio.GRCStudioPermissionDenied, match="enrolled"):
        store.preview_projection(
            "tenant-a",
            "enterprise-grc",
            projection_kind="questionnaire",
            definition_id="risk-intake",
            target_authority=stale,
            expected_active_version=1,
            expected_blueprint_sha256=selected.blueprint_sha256,
        )


def test_runtime_apply_double_resolves_and_validates_receipt(tmp_path: Path) -> None:
    actor = {"value": "author"}
    store = make_store(tmp_path, actor)
    selected = approve_release(
        store,
        actor,
        store.create_version(
            "tenant-a",
            "enterprise-grc",
            blueprint=blueprint(),
            expected_latest_version=0,
            operation_id="create-runtime",
        ),
        "runtime",
    )
    selected = store.publish(
        "tenant-a",
        "enterprise-grc",
        1,
        expected_revision=selected.revision,
        expected_integrity_sha256=selected.integrity_sha256,
        expected_active_version=0,
        expected_active_blueprint_sha256=None,
        expected_pointer_revision=0,
        operation_id="publish-runtime",
    )
    authority = studio.issue_runtime_target_authority(
        tenant_id="tenant-a",
        target_kind="report",
        target_id="report-catalog",
        target_revision=7,
        target_integrity_sha256="d" * 64,
        allowed_blueprint_sha256=selected.blueprint_sha256,
        valid_until=NOW + 100,
    )
    calls: list[str] = []

    def resolver(*_args):
        calls.append("resolve")
        return authority

    def applier(**kwargs):
        calls.append("apply")
        return {
            "schema": studio.APPLY_RECEIPT_SCHEMA,
            "operation_id": kwargs["operation_id"],
            "applied": True,
            "projection_sha256": kwargs["projection"]["projection_sha256"],
            "authority_sha256": kwargs["target_authority_sha256"],
            "target_revision_before": kwargs["expected_target_revision"],
            "target_revision_after": kwargs["expected_target_revision"] + 1,
            "target_integrity_sha256_after": "e" * 64,
        }

    receipt = store.apply_projection(
        "tenant-a",
        "enterprise-grc",
        projection_kind="report",
        definition_id="risk-register",
        target_id="report-catalog",
        target_revision=7,
        expected_active_version=1,
        expected_blueprint_sha256=selected.blueprint_sha256,
        operation_id="apply-report",
        authority_resolver=resolver,
        applier=applier,
    )
    assert receipt["applied"] is True
    assert calls == ["resolve", "resolve", "apply"]
    replay = store.apply_projection(
        "tenant-a",
        "enterprise-grc",
        projection_kind="report",
        definition_id="risk-register",
        target_id="report-catalog",
        target_revision=7,
        expected_active_version=1,
        expected_blueprint_sha256=selected.blueprint_sha256,
        operation_id="apply-report",
        authority_resolver=resolver,
        applier=applier,
    )
    assert replay == receipt
    assert calls == ["resolve", "resolve", "apply"]
    assert store.verify_integrity("tenant-a")["counts"]["operations"] == 6


def test_rejected_retention_recovery_and_concurrent_draft_cas(tmp_path: Path) -> None:
    actor = {"value": "author"}
    now = {"value": NOW}
    store = make_store(tmp_path, actor, now=now)
    version = store.create_version(
        "tenant-a",
        "enterprise-grc",
        blueprint=blueprint(),
        expected_latest_version=0,
        operation_id="create-reject",
    )
    version = store.submit_for_review(
        "tenant-a",
        "enterprise-grc",
        1,
        expected_revision=version.revision,
        expected_integrity_sha256=version.integrity_sha256,
        operation_id="submit-reject",
    )
    actor["value"] = "reviewer"
    version = store.review(
        "tenant-a",
        "enterprise-grc",
        1,
        accepted=False,
        rationale_ref="unsafe-definition",
        expected_revision=version.revision,
        expected_integrity_sha256=version.integrity_sha256,
        operation_id="reject-v1",
    )
    now["value"] += 86_401
    assert len(store.retention_due("tenant-a")) == 1
    purged = store.purge_expired("tenant-a")
    assert purged["purged_count"] == 1
    assert store.verify_integrity("tenant-a")["counts"]["tombstones"] == 1
    backup = store.create_recovery_backup("tenant-a")
    assert store.verify_recovery_backup("tenant-a", backup["backup_id"])["verified"] is True
    listed = store.list_recovery_backups("tenant-a")
    assert [row["backup_id"] for row in listed] == [backup["backup_id"]]
    assert set(listed[0]) == {"backup_id", "created_at"}
    foreign = {
        "schema": studio.RECOVERY_SCHEMA,
        "backup_id": "grc-1-foreign",
        "tenant_scope_sha256": "0" * 64,
        "created_at": 1,
    }
    (tmp_path / "recovery" / "grc-1-foreign.json").write_text(json.dumps(foreign))
    assert len(store.list_recovery_backups("tenant-a")) == 1

    actor["value"] = "author"
    current = store.create_version(
        "tenant-a",
        "enterprise-grc",
        blueprint=blueprint(),
        expected_latest_version=1,
        operation_id="create-concurrent",
    )
    other = make_store(tmp_path, actor, now=now)

    def replace(which: int):
        changed = blueprint()
        changed["name_ref"] = f"concurrent-{which}"
        return other.replace_draft(
            "tenant-a",
            "enterprise-grc",
            2,
            blueprint=changed,
            expected_revision=current.revision,
            expected_integrity_sha256=current.integrity_sha256,
            operation_id=f"concurrent-{which}",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = []
        for future in [pool.submit(replace, 1), pool.submit(replace, 2)]:
            try:
                outcomes.append(future.result())
            except studio.GRCStudioConflict:
                outcomes.append("conflict")
    assert sum(item == "conflict" for item in outcomes) == 1
