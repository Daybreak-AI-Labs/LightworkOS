from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def test_application_mounts_native_public_admin_and_receipt_key_routes(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", "test-tenant")
    app_module = importlib.import_module("maverick_dashboard.app")
    paths = list(app_module.app.openapi()["paths"])

    for expected in (
        "/api/v1/public/consent/native/enroll",
        "/api/v1/public/consent/native/refresh",
        "/api/v1/public/consent/native/dispatch",
        "/api/v1/public/consent/native/receipt-keys",
        "/api/v1/public/consent/native/receipt-keys/{application_ref}",
        "/api/v1/consent/native/applications",
        "/api/v1/consent/native/readiness",
        "/api/v1/consent/native/integrity",
        "/static/lightwork-consent-native-admin.js",
    ):
        assert paths.count(expected) == 1
    assert app_module._MAX_NATIVE_CONSENT_BODY_BYTES == 256 * 1_024

    # The native mount shares this integration block with the inventory workbench.
    # Keep this assertion so a future conflict resolution cannot drop that live mount.
    assert paths.count("/api/v1/governance/inventory/status") == 1

    client = TestClient(app_module.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    page = client.get("/consent/native")
    assert page.status_code == 200
    assert 'data-copilot-page="/consent/native"' in page.text
    asset = client.get("/static/lightwork-consent-native-admin.js")
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "no-store, private, max-age=0"
