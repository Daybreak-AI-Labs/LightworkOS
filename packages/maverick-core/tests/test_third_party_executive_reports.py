from __future__ import annotations

import sqlite3

import pytest
from maverick import third_party_executive_reports as reports


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def brand(**overrides: object) -> reports.BrandTokens:
    values = {
        "schema": reports.BRAND_SCHEMA,
        "organization_name": "Lightwork Test Estate",
        "report_title": "Third-party executive report",
        "footer_text": "Confidential governance record",
        "primary_color": "#102A43",
        "accent_color": "#2CB1BC",
        "text_color": "#243B53",
        "brand_asset_metadata_ref": "approved-logo-v2",
        "brand_asset_metadata_sha256": "1" * 64,
    }
    values.update(overrides)
    return reports.BrandTokens(**values)  # type: ignore[arg-type]


def snapshot(*, captured_at: float = 1_799_999_999.0, role: str = "operator"):
    return reports.ReportSnapshot(
        schema=reports.SNAPSHOT_SCHEMA,
        tenant_id="tenant-alpha",
        role_view=role,
        sources=(
            reports.SourceManifestEntry(
                reports.SOURCE_SCHEMA,
                "contract_record",
                "contract-1",
                "available",
                3,
                "2" * 64,
                1,
                "none",
            ),
            reports.SourceManifestEntry(
                reports.SOURCE_SCHEMA,
                "intelligence_vendor",
                "vendor-1",
                "unavailable",
                0,
                None,
                0,
                "source_unavailable",
            ),
        ),
        metrics=(
            reports.ReportMetric("available_record_count", 1),
            reports.ReportMetric("selected_record_count", 2),
            reports.ReportMetric("unavailable_record_count", 1),
        ),
        captured_at=captured_at,
    )


def store(
    tmp_path,
    clock: Clock,
    *,
    principal: list[str] | None = None,
    max_reports: int = 10,
):
    identity = principal or ["principal-operator"]
    token_number = [0]

    def token_factory() -> str:
        token_number[0] += 1
        return "tpr_" + f"{token_number[0]:043d}"

    config = reports.ThirdPartyExecutiveReportConfig(
        enable=True,
        max_reports=max_reports,
        max_sources=10,
        max_pdf_bytes=128 * 1024,
        retention_seconds=86_400,
        download_token_seconds=60,
    )
    return reports.ThirdPartyExecutiveReportStore(
        tmp_path / "reports.sqlite3",
        tenant_id="tenant-alpha",
        principal_resolver=lambda: identity[0],
        audit_authorizer=lambda: True,
        maintenance_authorizer=lambda: True,
        config_gate=lambda: None,
        config=config,
        clock=clock,
        id_factory=lambda: "report-fixed",
        token_factory=token_factory,
    )


def test_pdf_is_deterministic_bounded_and_contains_no_active_content() -> None:
    first = reports.render_deterministic_pdf(
        report_id="report-fixed",
        brand=brand(),
        snapshot=snapshot(),
        created_at=1_800_000_000.0,
        maximum_bytes=128 * 1024,
    )
    second = reports.render_deterministic_pdf(
        report_id="report-fixed",
        brand=brand(),
        snapshot=snapshot(),
        created_at=1_800_000_000.0,
        maximum_bytes=128 * 1024,
    )
    assert first == second
    assert first.startswith(b"%PDF-1.4")
    assert first.endswith(b"%%EOF\n")
    assert b"/JavaScript" not in first
    assert b"/URI" not in first
    assert b"/XObject" not in first
    assert b"No brand asset bytes were resolved or embedded." in first
    assert len(first) < 128 * 1024
    with pytest.raises(reports.ThirdPartyExecutiveReportValidationError):
        brand(organization_name="<style>bad</style>").normalized()
    with pytest.raises(reports.ThirdPartyExecutiveReportValidationError):
        brand(organization_name="https://example.test").normalized()


def test_pdf_paginates_by_vertical_budget_so_no_line_lands_in_the_footer() -> None:
    """A report with every metric plus several sources must not overflow
    the page (lines drawn at y=2, below the y=34 footer): pagination counts
    the vertical space lines consume, not the number of lines."""
    import re

    metrics = tuple(reports.ReportMetric(m, 1) for m in sorted(reports.METRIC_IDS))
    sources = tuple(
        reports.SourceManifestEntry(
            reports.SOURCE_SCHEMA, "contract_record", f"contract-{i}",
            "available", 3, "2" * 64, 1, "none",
        )
        for i in range(6)
    )
    heavy = reports.ReportSnapshot(
        schema=reports.SNAPSHOT_SCHEMA,
        tenant_id="tenant-alpha",
        role_view="operator",
        sources=sources,
        metrics=metrics,
        captured_at=1_799_999_999.0,
    )
    pdf = reports.render_deterministic_pdf(
        report_id="report-fixed",
        brand=brand(),
        snapshot=heavy,
        created_at=1_800_000_000.0,
        maximum_bytes=128 * 1024,
    )
    # (font size, baseline) per text operator; the 8pt footer at y=34 is the
    # one line allowed in the footer band.
    placed = [
        (int(size), int(y))
        for size, y in re.findall(rb"/F\d (\d+) Tf\n[\d. ]+ rg\n54 (-?\d+) Td", pdf)
    ]
    assert placed, "no text operators rendered"
    body_ys = [y for size, y in placed if size != 8]
    footer_ys = [y for size, y in placed if size == 8]
    assert body_ys and footer_ys
    assert set(footer_ys) == {34}
    # Every body line stays above the footer band; nothing is clipped or
    # overprinted on the page edge.
    assert min(body_ys) >= 50, min(body_ys)
    # Every source digest (the report's evidence) made it onto a page.
    assert pdf.count(b"digest 2222") == 6
    # Still deterministic.
    again = reports.render_deterministic_pdf(
        report_id="report-fixed",
        brand=brand(),
        snapshot=heavy,
        created_at=1_800_000_000.0,
        maximum_bytes=128 * 1024,
    )
    assert pdf == again


def test_create_is_immutable_idempotent_role_aware_and_integrity_verified(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock)
    created = authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        report_id="report-fixed",
        expected_absent_revision=0,
        idempotency_key="create-report-0001",
    )
    replay = authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        report_id="report-fixed",
        expected_absent_revision=0,
        idempotency_key="create-report-0001",
    )
    assert replay == created
    assert created.state == "active"
    assert created.control_revision == 1
    assert created.artifact_available is True
    assert created.snapshot.live_portfolio_acceptance_verified is False
    assert authority.get_report("report-fixed", caller_role="operator") == created
    assert authority.get_report("report-fixed", caller_role="admin") == created
    with pytest.raises(reports.ThirdPartyExecutiveReportPermissionDenied):
        authority.get_report("report-fixed", caller_role="viewer")
    verification = authority.verify_integrity()
    assert verification.reports == 1
    assert verification.artifacts == 1
    assert verification.audit_events == 1
    assert authority.audit_history()[0]["action"] == "report_created"


def test_one_time_principal_bound_download_and_revocation(tmp_path) -> None:
    clock = Clock()
    principal = ["principal-operator"]
    authority = store(tmp_path, clock, principal=principal)
    authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        report_id="report-fixed",
        idempotency_key="create-report-0002",
    )
    grant = authority.issue_download_grant(
        "report-fixed",
        caller_role="operator",
        expected_control_revision=1,
        idempotency_key="issue-download-0001",
    )
    assert grant.token is not None and grant.token_disclosed is True
    replay = authority.issue_download_grant(
        "report-fixed",
        caller_role="operator",
        expected_control_revision=1,
        idempotency_key="issue-download-0001",
    )
    assert replay.token is None and replay.idempotent_replay is True
    database = (tmp_path / "reports.sqlite3").read_bytes()
    assert grant.token.encode() not in database
    artifact = authority.redeem_download_token(grant.token, caller_role="operator")
    assert artifact.pdf_bytes.startswith(b"%PDF-1.4")
    with pytest.raises(reports.ThirdPartyExecutiveReportConflict):
        authority.redeem_download_token(grant.token, caller_role="operator")

    second = authority.issue_download_grant(
        "report-fixed",
        caller_role="operator",
        expected_control_revision=1,
        idempotency_key="issue-download-0002",
    )
    revoked = authority.revoke_report(
        "report-fixed",
        expected_control_revision=1,
        reason_code="superseded",
        idempotency_key="revoke-report-0001",
    )
    assert revoked.state == "revoked" and revoked.control_revision == 2
    with pytest.raises(reports.ThirdPartyExecutiveReportConflict):
        authority.redeem_download_token(second.token or "", caller_role="operator")
    assert authority.verify_integrity().audit_events == 5


def test_download_grant_hides_tenant_and_state_from_wrong_principal(tmp_path) -> None:
    clock = Clock()
    principal = ["principal-operator"]
    authority = store(tmp_path, clock, principal=principal)
    authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        idempotency_key="create-report-0003",
    )
    grant = authority.issue_download_grant(
        "report-fixed",
        caller_role="operator",
        expected_control_revision=1,
        idempotency_key="issue-download-0003",
    )
    principal[0] = "principal-other"
    with pytest.raises(reports.ThirdPartyExecutiveReportNotFound):
        authority.redeem_download_token(grant.token or "", caller_role="operator")


def test_retention_replaces_report_with_privacy_minimized_tombstone(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock)
    created = authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        idempotency_key="create-report-0004",
    )
    clock.value = created.retained_until + 1
    assert authority.purge_expired(limit=10, idempotency_key="purge-reports-0001") == (
        "report-fixed",
    )
    expired = authority.get_report("report-fixed", caller_role="operator")
    assert isinstance(expired, reports.ExecutiveReportTombstone)
    assert expired.original_content_sha256 == created.content_sha256
    assert expired.state == "expired"
    assert expired.artifact_available is False
    database = tmp_path / "reports.sqlite3"
    with sqlite3.connect(database) as connection:
        content_json, tombstoned_at = connection.execute(
            "SELECT content_json,tombstoned_at FROM executive_reports "
            "WHERE report_id='report-fixed'"
        ).fetchone()
        assert connection.execute(
            "SELECT COUNT(*) FROM executive_report_controls"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM executive_report_operations WHERE report_id IS NOT NULL"
        ).fetchone()[0] == 0
    assert tombstoned_at == expired.purged_at
    assert reports.TOMBSTONE_SCHEMA in content_json
    for private_value in (
        "Lightwork Test Estate",
        "principal-operator",
        "contract-1",
        "vendor-1",
        "approved-logo-v2",
    ):
        assert private_value not in content_json
    verification = authority.verify_integrity()
    assert verification.artifacts == 0
    assert verification.tombstones == 1


def test_expired_tombstones_do_not_consume_artifact_capacity(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock, max_reports=1)
    first = authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        report_id="report-first",
        idempotency_key="create-capacity-report-0001",
    )
    clock.value = first.retained_until + 1
    assert authority.purge_expired(
        limit=1,
        idempotency_key="purge-capacity-report-0001",
    ) == ("report-first",)
    second = authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        report_id="report-second",
        idempotency_key="create-capacity-report-0002",
    )
    assert second.report_id == "report-second"
    assert authority.get_report("report-first", caller_role="operator").state == "expired"


def test_tombstones_operations_and_audit_are_capacity_bounded(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock, max_reports=1)
    for index in range(40):
        report_id = f"report-bounded-{index:04d}"
        authority.create_report(
            snapshot=snapshot(),
            brand=brand(),
            report_id=report_id,
            idempotency_key=f"create-bounded-report-{index:04d}",
        )
        assert authority.purge_expired(
            limit=1,
            idempotency_key=f"purge-bounded-report-{index:04d}",
        ) == ()
        clock.value += 86_401
        assert authority.purge_expired(
            limit=1,
            idempotency_key=f"purge-bounded-expired-{index:04d}",
        ) == (report_id,)

    verification = authority.verify_integrity()
    assert verification.tombstones <= 1
    assert verification.operations <= 32
    assert verification.audit_events <= 32
    assert verification.audit_checkpoint_sequence > 0
    assert verification.audit_checkpoint_sha256 != reports.GENESIS_SHA256
    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM executive_reports WHERE tombstoned_at IS NOT NULL"
        ).fetchone()[0] <= 1
        checkpoint_json = connection.execute(
            "SELECT checkpoint_json FROM executive_report_audit_checkpoint WHERE singleton=1"
        ).fetchone()[0]
        assert "compacted_through_sequence" in checkpoint_json


def test_audit_checkpoint_tampering_after_compaction_fails_closed(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock, max_reports=1)
    for index in range(18):
        report_id = f"report-checkpoint-{index:04d}"
        created = authority.create_report(
            snapshot=snapshot(),
            brand=brand(),
            report_id=report_id,
            idempotency_key=f"create-checkpoint-{index:04d}",
        )
        clock.value = created.retained_until + 1
        authority.purge_expired(
            limit=1,
            idempotency_key=f"purge-checkpoint-{index:04d}",
        )
    assert authority.verify_integrity().audit_checkpoint_sequence > 0
    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        connection.execute(
            "UPDATE executive_report_audit_checkpoint SET checkpoint_json=? WHERE singleton=1",
            ('{"forged":true}',),
        )
        connection.commit()
    with pytest.raises(
        reports.ThirdPartyExecutiveReportIntegrityError,
        match="audit_checkpoint_integrity_failed",
    ):
        authority.verify_integrity()


def test_download_grant_capacity_is_bounded_and_stale_grants_are_retired(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock, max_reports=1)
    authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        report_id="report-fixed",
        idempotency_key="create-grant-capacity-0001",
    )
    for index in range(4):
        authority.issue_download_grant(
            "report-fixed",
            caller_role="operator",
            expected_control_revision=1,
            idempotency_key=f"issue-capacity-grant-{index:04d}",
        )
    with pytest.raises(
        reports.ThirdPartyExecutiveReportConflict,
        match="executive_report_download_grant_capacity_exceeded",
    ):
        authority.issue_download_grant(
            "report-fixed",
            caller_role="operator",
            expected_control_revision=1,
            idempotency_key="issue-capacity-grant-0004",
        )
    clock.value += 61
    replacement = authority.issue_download_grant(
        "report-fixed",
        caller_role="operator",
        expected_control_revision=1,
        idempotency_key="issue-capacity-grant-0005",
    )
    assert replacement.token_disclosed is True
    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM executive_report_download_grants"
        ).fetchone()[0] == 1
    assert authority.verify_integrity().grants == 1


def test_pdf_and_control_tampering_fail_closed(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock)
    authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        idempotency_key="create-report-0005",
    )
    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        connection.execute(
            "UPDATE executive_report_artifacts SET pdf_blob=? WHERE report_id=?",
            (b"not-a-pdf", "report-fixed"),
        )
        connection.commit()
    with pytest.raises(reports.ThirdPartyExecutiveReportIntegrityError):
        authority.verify_integrity()


def test_idempotency_operation_result_tampering_fails_closed(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock)
    authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        report_id="report-fixed",
        idempotency_key="create-operation-integrity-0001",
    )
    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        connection.execute(
            "UPDATE executive_report_operations SET result_json=?",
            ('{"report_id":"report-forged"}',),
        )
        connection.commit()
    with pytest.raises(
        reports.ThirdPartyExecutiveReportIntegrityError,
        match="executive_report_operation_integrity_failed",
    ):
        authority.verify_integrity()


def test_schema_v1_canonical_operations_migrate_to_integrity_protection(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock)
    authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        report_id="report-fixed",
        idempotency_key="create-operation-migration-0001",
    )
    path = tmp_path / "reports.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "ALTER TABLE executive_report_operations DROP COLUMN integrity_sha256"
        )
        connection.execute(
            "UPDATE executive_report_meta SET value='1' WHERE key='schema_version'"
        )
        connection.commit()
    migrated = store(tmp_path, clock)
    assert migrated.verify_integrity().operations == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT value FROM executive_report_meta WHERE key='schema_version'"
        ).fetchone()[0] == "3"
        digest = connection.execute(
            "SELECT integrity_sha256 FROM executive_report_operations"
        ).fetchone()[0]
    assert isinstance(digest, str) and len(digest) == 64


def test_schema_v2_expired_content_migrates_to_minimal_tombstone(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock)
    created = authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        report_id="report-fixed",
        idempotency_key="create-v2-migration-0001",
    )
    control = {
        "schema": reports.CONTROL_SCHEMA,
        "report_id": "report-fixed",
        "state": "expired",
        "control_revision": 2,
        "revoked_at": None,
        "revocation_reason": None,
    }
    control_json = reports._canonical(control).decode("ascii")
    path = tmp_path / "reports.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM executive_report_artifacts")
        connection.execute(
            "UPDATE executive_report_controls SET control_json=?,control_sha256=?",
            (control_json, reports.canonical_sha256(control)),
        )
        connection.execute("ALTER TABLE executive_reports DROP COLUMN tombstoned_at")
        connection.execute("ALTER TABLE executive_report_audit DROP COLUMN occurred_at")
        connection.execute("DROP TABLE executive_report_audit_checkpoint")
        connection.execute(
            "UPDATE executive_report_meta SET value='2' WHERE key='schema_version'"
        )
        connection.commit()
    clock.value = created.retained_until + 1

    migrated = store(tmp_path, clock)
    tombstone = migrated.get_report("report-fixed", caller_role="operator")
    assert isinstance(tombstone, reports.ExecutiveReportTombstone)
    assert tombstone.original_content_sha256 == created.content_sha256
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT value FROM executive_report_meta WHERE key='schema_version'"
        ).fetchone()[0] == "3"
        assert connection.execute(
            "SELECT COUNT(*) FROM executive_report_controls"
        ).fetchone()[0] == 0
        content_json = connection.execute(
            "SELECT content_json FROM executive_reports WHERE report_id='report-fixed'"
        ).fetchone()[0]
    assert "contract-1" not in content_json
    assert reports.TOMBSTONE_SCHEMA in content_json


def test_grant_index_tampering_and_missing_artifact_fail_closed(tmp_path) -> None:
    clock = Clock()
    authority = store(tmp_path, clock)
    authority.create_report(
        snapshot=snapshot(),
        brand=brand(),
        idempotency_key="create-report-0006",
    )
    authority.issue_download_grant(
        "report-fixed",
        caller_role="operator",
        expected_control_revision=1,
        idempotency_key="issue-download-0006",
    )
    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        connection.execute(
            "UPDATE executive_report_download_grants SET expires_at=expires_at+100"
        )
        connection.commit()
    with pytest.raises(reports.ThirdPartyExecutiveReportIntegrityError):
        authority.verify_integrity()

    other = tmp_path / "missing.sqlite3"
    intact = reports.ThirdPartyExecutiveReportStore(
        other,
        tenant_id="tenant-alpha",
        principal_resolver=lambda: "principal-operator",
        audit_authorizer=lambda: True,
        maintenance_authorizer=lambda: True,
        config_gate=lambda: None,
        config=reports.ThirdPartyExecutiveReportConfig(
            enable=True,
            max_reports=10,
            max_sources=10,
            max_pdf_bytes=128 * 1024,
            retention_seconds=86_400,
            download_token_seconds=60,
        ),
        clock=clock,
        id_factory=lambda: "report-fixed",
    )
    intact.create_report(
        snapshot=snapshot(),
        brand=brand(),
        idempotency_key="create-report-0007",
    )
    with sqlite3.connect(other) as connection:
        connection.execute("DELETE FROM executive_report_artifacts")
        connection.commit()
    with pytest.raises(reports.ThirdPartyExecutiveReportIntegrityError):
        intact.get_report("report-fixed", caller_role="operator")


def test_config_is_default_off_and_closed() -> None:
    assert reports.ThirdPartyExecutiveReportConfig.from_mapping({}).enable is False
    configured = reports.ThirdPartyExecutiveReportConfig.from_mapping(
        {
            "third_party_management": {
                "enable": True,
                "executive_reports": {
                    "enable": True,
                    "max_reports": 50,
                    "max_sources": 20,
                    "max_pdf_bytes": 131_072,
                    "retention_seconds": 86_400,
                    "download_token_seconds": 120,
                }
            }
        }
    )
    assert configured.enable is True and configured.max_sources == 20
    with pytest.raises(reports.ThirdPartyExecutiveReportConfigError):
        reports.ThirdPartyExecutiveReportConfig.from_mapping(
            {"third_party_management": {"executive_reports": {"unknown": True}}}
        )


def test_historical_reports_page_reaches_oldest_and_keeps_exact_role(tmp_path):
    clock = Clock()
    authority = store(tmp_path, clock, max_reports=600)
    for index in range(501):
        authority.create_report(snapshot=snapshot(), brand=brand(), report_id=f"report-{index:04d}",
                                idempotency_key=f"history-create-{index:04d}")
        clock.value += 1
    assert "report-0000" not in {row.report_id for row in authority.list_reports(caller_role="operator", limit=500)}
    page = authority.history_window(caller_role="operator", offset=500)
    assert [row.report_id for row in page.rows] == ["report-0000"]
    assert page.next_offset is None
    assert authority.history_window(caller_role="operator", oldest=True).rows[0].report_id == "report-0000"
    hidden = authority.history_window(caller_role="viewer")
    assert hidden.rows == [] and hidden.next_offset is None
    before = authority.history_window(caller_role="operator", oldest=True).snapshot
    authority.revoke_report("report-0000", expected_control_revision=1, reason_code="superseded", idempotency_key="history-revoke-0000")
    assert before != authority.history_window(caller_role="operator", oldest=True).snapshot
