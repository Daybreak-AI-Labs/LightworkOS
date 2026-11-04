"""List endpoints behind the Trust Center brand section of the access page."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick.trust_center_branding import (
    BrandPublicationAuthority,
    TrustCenterBrandingConfig,
    TrustCenterBrandingStore,
)
from maverick_dashboard import trust_center_branding_api as api

API = "/api/v1/consent/trust-center-branding"
PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def _store(path: Path, tenant: str) -> TrustCenterBrandingStore:
    return TrustCenterBrandingStore(
        path / f"{tenant}.sqlite3",
        tenant_id=tenant,
        config=TrustCenterBrandingConfig(
            enable=True,
            key_revision=1,
            retention_seconds=60,
            challenge_ttl_seconds=300,
            verification_ttl_seconds=900,
        ),
        key_resolver=lambda _tenant, _ref, _revision: b"k" * 32,
        publication_resolver=lambda _property, _client: BrandPublicationAuthority(
            tenant_id=tenant,
            property_id="property-a",
            property_revision=1,
            publication_id="publication-a",
            publication_revision=1,
            publication_sha256="a" * 64,
            bundle_sha256="b" * 64,
            client_credential_id="client-a",
            client_revision=1,
            client_record_sha256="c" * 64,
            public_origin="https://brand.example.com",
        ),
        token_factory=lambda: "challenge-token-with-at-least-32-bytes",
    )


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tenant = {"value": "tenant-a"}
    permissions: list[str] = []
    monkeypatch.setattr(api, "trust_center_branding_enabled", lambda: True)
    monkeypatch.setattr(api, "_tenant_id", lambda: tenant["value"])
    monkeypatch.setattr(api, "require_permission", lambda _r, p: permissions.append(p))
    monkeypatch.setattr(api, "require_global_permission", lambda _r, p: permissions.append(p))
    stores: dict[str, TrustCenterBrandingStore] = {}
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(sub=request.headers.get("x-user", "alice"))
        return await call_next(request)

    def factory(*, tenant_id: str, request: Request):
        del request
        if tenant_id not in stores:
            stores[tenant_id] = _store(tmp_path, tenant_id)
        return stores[tenant_id]

    app.state.trust_center_branding_store_factory = factory
    app.include_router(api.router, prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), tenant, permissions


def test_lists_are_view_gated_and_workspace_scoped(client) -> None:
    http, tenant, permissions = client
    assert http.get(f"{API}/assets").json() == {"items": []}
    proposed = http.post(
        f"{API}/assets/trust-center-logo/versions",
        json={
            "expected_version": 0,
            "asset_kind": "logo",
            "media_type": "image/png",
            "content_base64": base64.b64encode(PNG_1X1).decode(),
        },
    )
    assert proposed.status_code == 201, proposed.text
    assets = http.get(f"{API}/assets").json()["items"]
    assert [(item["asset_id"], item["state"]) for item in assets] == [
        ("trust-center-logo", "pending_review")
    ]
    challenged = http.post(
        f"{API}/domains/trust-example/challenges",
        json={"host": "trust.example.com", "expected_claim_version": 0},
    )
    assert challenged.status_code == 201, challenged.text
    domains = http.get(f"{API}/domains").json()["items"]
    assert [item["host"] for item in domains] == ["trust.example.com"]
    assert "dns_challenge_token" not in str(domains)
    assert http.get(f"{API}/projections").json() == {"items": []}
    assert permissions.count("view") >= 4
    tenant["value"] = "tenant-b"
    assert http.get(f"{API}/assets").json() == {"items": []}
    assert http.get(f"{API}/domains").json() == {"items": []}
