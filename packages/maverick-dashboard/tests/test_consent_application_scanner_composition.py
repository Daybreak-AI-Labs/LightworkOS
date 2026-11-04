from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from maverick.paths import tenant_scope
from maverick_dashboard import consent_application_scanner_composition as composition

TENANT = "tenant-a"


def _config(*, enabled: bool = True, consent_enabled: bool = True) -> dict[str, object]:
    return {
        "consent_preferences": {
            "enable": consent_enabled,
            "application_scanner": {
                "enable": enabled,
                "max_records": 321,
                "retention_seconds": 86_400,
            },
        }
    }


def _request(app: FastAPI) -> Request:
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/api/v1/consent/application-scans/readiness",
            "raw_path": b"/api/v1/consent/application-scans/readiness",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 443),
            "app": app,
        }
    )
    request.state.principal = SimpleNamespace(principal="user:admin")
    return request


def test_settings_are_closed_default_off_and_parent_gated() -> None:
    assert composition.consent_application_scanner_settings({}) is None
    assert composition.consent_application_scanner_settings(_config(enabled=False)) is None
    assert composition.consent_application_scanner_settings(_config()) == (
        composition.ConsentApplicationScannerSettings(
            max_records=321,
            retention_seconds=86_400,
        )
    )
    with pytest.raises(composition.ConsentApplicationScannerCompositionError, match="requires"):
        composition.consent_application_scanner_settings(_config(consent_enabled=False))
    invalid = _config()
    invalid["consent_preferences"]["application_scanner"]["raw_bytes"] = True  # type: ignore[index]
    with pytest.raises(composition.ConsentApplicationScannerCompositionError, match="unknown"):
        composition.consent_application_scanner_settings(invalid)


def test_attach_is_lazy_and_request_tenant_exact(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setattr(composition, "_load_tenant_config", lambda tenant: _config())
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    app = FastAPI()
    composition.attach_consent_application_scanner_composition(app)
    request = _request(app)

    with tenant_scope(tenant=TENANT):
        assert app.state.consent_application_scanner_enabled_probe(TENANT) is True
        assert app.state.consent_application_scanner_readiness_probe(request, TENANT) is True
        service = app.state.consent_application_scanner_service_factory(request, TENANT)
        assert service.verify_integrity(limit=1)["ok"] is True
        assert app.state.consent_application_scanner_service_factory(request, TENANT) is service
        with pytest.raises(TypeError):
            app.state.consent_application_scanner_maintenance(
                request,
                TENANT,
                actor="retention-worker",
                limit=1,
                now=2_000_000_000.0,
            )

    other_app = FastAPI()
    with tenant_scope(tenant=TENANT):
        with pytest.raises(
            composition.ConsentApplicationScannerCompositionError,
            match="request authority",
        ):
            app.state.consent_application_scanner_service_factory(
                _request(other_app),
                TENANT,
            )
    with tenant_scope(tenant="tenant-b"):
        with pytest.raises(
            composition.ConsentApplicationScannerCompositionError,
            match="tenant authority",
        ):
            app.state.consent_application_scanner_service_factory(request, TENANT)


def test_disabled_or_malformed_config_fails_closed(monkeypatch) -> None:
    selected = {"config": _config(enabled=False)}
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: selected["config"],
    )
    assert composition.consent_application_scanner_enabled(TENANT) is False
    selected["config"] = {"consent_preferences": {"enable": True, "application_scanner": []}}
    assert composition.consent_application_scanner_enabled(TENANT) is False


def test_production_app_mounts_scanner_routes_assets_and_composition() -> None:
    from maverick_dashboard.app import app

    def mounted_paths(routes, prefix=""):
        for route in routes:
            included = getattr(route, "original_router", None)
            if included is not None:
                context = route.include_context
                yield from mounted_paths(
                    included.routes,
                    prefix + str(getattr(context, "prefix", "")),
                )
            else:
                yield prefix + str(getattr(route, "path", ""))

    paths = set(mounted_paths(app.routes))
    assert "/consent/application-scans" in paths
    assert "/api/v1/consent/application-scans/readiness" in paths
    assert "/api/v1/consent/application-scans/applications" in paths
    assert "/api/v1/consent/application-scans/scans/{scan_id}/review" in paths
    assert "/static/lightwork-consent-application-scanner.css" in paths
    assert "/static/lightwork-consent-application-scanner.js" in paths
    for dependency in (
        "consent_application_scanner_service_factory",
        "consent_application_scanner_enabled_probe",
        "consent_application_scanner_readiness_probe",
        "consent_application_scanner_maintenance",
    ):
        assert callable(getattr(app.state, dependency, None))
