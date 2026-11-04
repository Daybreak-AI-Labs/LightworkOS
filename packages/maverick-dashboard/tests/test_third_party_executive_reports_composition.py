from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick import third_party_executive_reports as reports
from maverick_dashboard import third_party_executive_reports_composition as composition
from starlette.requests import Request


def _request(
    app: FastAPI,
    subject: str | None = "user:operator",
    *,
    authorization: str | None = None,
) -> Request:
    headers = [] if authorization is None else [(b"authorization", authorization.encode())]
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": headers,
            "query_string": b"",
            "server": ("127.0.0.1", 80),
            "client": ("127.0.0.1", 50000),
            "scheme": "http",
            "app": app,
        }
    )
    if subject is not None:
        request.state.principal = SimpleNamespace(principal=subject)
    return request


def _settings() -> reports.ThirdPartyExecutiveReportConfig:
    return reports.ThirdPartyExecutiveReportConfig(
        enable=True,
        max_reports=50,
        max_sources=20,
        max_pdf_bytes=128 * 1024,
        retention_seconds=86_400,
        download_token_seconds=120,
    )


def test_install_is_lazy_idempotent_and_exposes_stable_seams(monkeypatch) -> None:
    app = FastAPI()
    opened: list[str] = []
    app.state.third_party_executive_reports_store_path_factory = (
        lambda **_kwargs: opened.append("opened")
    )
    monkeypatch.setattr(
        composition,
        "third_party_executive_reports_enabled",
        lambda _tenant: True,
    )
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())
    composition.install_third_party_executive_reports_composition(app)
    composition.install_third_party_executive_reports_composition(app)
    assert opened == []
    assert app.state.third_party_executive_reports_composition_installed is True
    assert callable(app.state.third_party_executive_reports_runtime_factory)
    assert callable(app.state.third_party_executive_reports_source_resolver_factory)
    assert app.state.third_party_executive_reports_enabled_probe("tenant-alpha") is True
    assert app.state.third_party_executive_reports_readiness_probe("tenant-alpha") is True


def test_source_resolver_projects_safe_exact_records_and_unavailable_sources() -> None:
    app = FastAPI()
    vendor = SimpleNamespace(
        vendor_id="vendor-1",
        state="active",
        criticality=5,
        inherent_risk_level=4,
        revision=7,
        integrity_sha256="a" * 64,
        encrypted_profile_ref="must-not-project",
        profile_key_ref="must-not-project",
    )

    class Intelligence:
        def get_vendor(self, tenant_id, vendor_id):
            assert tenant_id == "tenant-alpha" and vendor_id == "vendor-1"
            return vendor

    app.state.third_party_intelligence_store_factory = lambda **_kwargs: Intelligence()
    resolver = composition.ThirdPartyReportSourceResolver(
        app,
        tenant_id="tenant-alpha",
        request=_request(app),
    )
    snapshot = resolver.resolve(
        (
            reports.SourceSelector("intelligence_vendor", "vendor-1"),
            reports.SourceSelector("contract_record", "contract-absent"),
        ),
        role_view="operator",
        captured_at=1_800_000_000.0,
        max_sources=20,
    )
    by_kind = {item.source_kind: item for item in snapshot.sources}
    assert by_kind["intelligence_vendor"].revision == 7
    assert by_kind["intelligence_vendor"].integrity_sha256 == "a" * 64
    assert by_kind["contract_record"].state == "unavailable"
    assert by_kind["contract_record"].reason_code == "source_not_configured"
    metrics = {item.metric_id: item.value for item in snapshot.metrics}
    assert metrics["selected_record_count"] == 2
    assert metrics["available_record_count"] == 1
    assert metrics["unavailable_record_count"] == 1
    assert metrics["critical_vendor_count"] == 1
    assert "must-not-project" not in repr(snapshot)


def test_runtime_derives_principal_role_and_creates_empty_truthful_report(
    tmp_path,
    monkeypatch,
) -> None:
    app = FastAPI()
    request = _request(app)
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())
    monkeypatch.setattr(composition, "_role", lambda _request: "operator")
    app.state.third_party_executive_reports_store_path_factory = (
        lambda **_kwargs: tmp_path / "reports.sqlite3"
    )
    app.state.third_party_executive_reports_source_resolver_factory = (
        lambda **kwargs: composition.ThirdPartyReportSourceResolver(
            app,
            tenant_id=kwargs["tenant_id"],
            request=kwargs["request"],
        )
    )
    runtime = composition._build_runtime(  # noqa: SLF001
        app,
        tenant_id="tenant-alpha",
        request=request,
    )
    created = runtime.create_report(
        selectors=(),
        brand=reports.BrandTokens(
            reports.BRAND_SCHEMA,
            "Lightwork",
            "Empty portfolio report",
            "Governed record",
            "#102A43",
            "#2CB1BC",
            "#243B53",
        ),
        report_id="empty-report",
        expected_absent_revision=0,
        idempotency_key="create-empty-report-0001",
    )
    assert created.tenant_id == "tenant-alpha"
    assert created.role_view == "operator"
    assert created.snapshot.sources == ()
    assert {item.metric_id: item.value for item in created.snapshot.metrics} == {
        "available_record_count": 0,
        "selected_record_count": 0,
        "unavailable_record_count": 0,
    }
    assert created.created_by_ref.startswith("tper-principal-")
    assert "user:operator" not in created.created_by_ref


def test_static_dashboard_bearer_maps_to_operator_principal_without_admin(
    tmp_path,
    monkeypatch,
) -> None:
    app = FastAPI()
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "executive-report-secret")
    request = _request(
        app,
        None,
        authorization="Bearer executive-report-secret",
    )
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())
    app.state.third_party_executive_reports_store_path_factory = (
        lambda **_kwargs: tmp_path / "reports.sqlite3"
    )
    app.state.third_party_executive_reports_source_resolver_factory = (
        lambda **kwargs: composition.ThirdPartyReportSourceResolver(
            app,
            tenant_id=kwargs["tenant_id"],
            request=kwargs["request"],
        )
    )
    runtime = composition._build_runtime(  # noqa: SLF001
        app,
        tenant_id="tenant-alpha",
        request=request,
    )
    assert composition._subject(request) == "dashboard-static-operator"  # noqa: SLF001
    assert runtime.role_view == "operator"
    created = runtime.create_report(
        selectors=(),
        brand=reports.BrandTokens(
            reports.BRAND_SCHEMA,
            "Lightwork",
            "Static bearer report",
            "Governed record",
            "#102A43",
            "#2CB1BC",
            "#243B53",
        ),
        report_id="static-report",
        expected_absent_revision=0,
        idempotency_key="create-static-report-0001",
    )
    assert created.role_view == "operator"
    with pytest.raises(
        reports.ThirdPartyExecutiveReportPermissionDenied,
        match="executive_report_maintenance_denied",
    ):
        runtime.store.revoke_report(
            "static-report",
            expected_control_revision=1,
            reason_code="superseded",
            idempotency_key="revoke-static-report-0001",
        )
    invalid = _request(app, None, authorization="Bearer wrong-secret")
    with pytest.raises(
        reports.ThirdPartyExecutiveReportPermissionDenied,
        match="executive_report_principal_unavailable",
    ):
        composition._subject(invalid)  # noqa: SLF001


def test_source_revision_drift_fails_closed() -> None:
    app = FastAPI()
    revisions = iter((1, 2))

    class Intelligence:
        def get_vendor(self, _tenant_id, _vendor_id):
            return SimpleNamespace(
                state="active",
                criticality=1,
                inherent_risk_level=1,
                revision=next(revisions),
                integrity_sha256="b" * 64,
            )

    app.state.third_party_intelligence_store_factory = lambda **_kwargs: Intelligence()
    resolver = composition.ThirdPartyReportSourceResolver(
        app,
        tenant_id="tenant-alpha",
        request=_request(app),
    )
    try:
        resolver.resolve_one(reports.SourceSelector("intelligence_vendor", "vendor-1"))
    except reports.ThirdPartyExecutiveReportConflict as exc:
        assert exc.error_code == "executive_report_source_changed"
    else:
        raise AssertionError("source revision drift did not fail closed")
