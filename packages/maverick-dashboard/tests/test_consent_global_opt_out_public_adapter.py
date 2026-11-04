from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import APIRouter, FastAPI, Request
from fastapi.testclient import TestClient
from maverick import consent_global_opt_out as goo
from maverick_dashboard.consent_global_opt_out_composition import (
    GlobalOptOutPublicMaterial,
)
from maverick_dashboard.consent_global_opt_out_public_adapter import (
    GlobalOptOutPublicRouteDependencies,
    attach_consent_global_opt_out_public_routes,
    global_opt_out_preflight_contracts,
)


class _Store:
    def __init__(self) -> None:
        self.error = None
        self.calls = []

    def get_public_configuration(self, authority):
        self.calls.append(("get", authority))
        if self.error:
            raise self.error
        return {
            "schema": goo.PUBLIC_CONFIG_SCHEMA,
            "configuration_version": 2,
            "configuration_sha256": "a" * 64,
            "authority_revision": 4,
            "authority_sha256": "b" * 64,
        }

    def submit(self, authority, **kwargs):
        self.calls.append(("submit", authority, kwargs))
        if self.error:
            raise self.error
        return {
            "schema": goo.PUBLIC_SUBMISSION_SCHEMA,
            "submission_id": "GOO-S" + "c" * 48,
            "state": "submitted",
            "case_reference_sha256": "d" * 64,
            "dsar_result_sha256": "e" * 64,
        }


def _app(store: _Store):
    authority = SimpleNamespace(binding=SimpleNamespace(tenant_id="alpha"))
    profile = SimpleNamespace(binding_sha256="f" * 64)
    contract = SimpleNamespace(public_configuration={"configuration_sha256": "1" * 64}, policy={})
    rights = object()
    public_authority = object()

    async def authenticate(_request: Request):
        return authority

    async def profile_authority(_request, received):
        assert received is authority
        return profile

    async def active_contract(_request, received):
        assert received is authority
        return contract

    async def rights_material(_request, received):
        assert received is authority
        return rights, profile

    def reauthenticate(_request, received, received_profile):
        assert received is authority
        assert received_profile is profile
        return lambda: object()

    def private_headers(response, _request, received):
        assert received is authority
        response.headers["Cache-Control"] = "no-store, private"

    dependencies = GlobalOptOutPublicRouteDependencies(
        authenticate=authenticate,
        profile_authority=profile_authority,
        active_contract=active_contract,
        rights_intake_material=rights_material,
        public_authority_reauthenticator=reauthenticate,
        set_private_headers=private_headers,
    )
    app = FastAPI()

    def factory(**kwargs):
        assert kwargs["tenant_id"] == "alpha"
        assert kwargs["initial_profile_binding"] is profile
        assert kwargs["active_public_configuration"] is contract.public_configuration
        assert kwargs["active_policy"] is contract.policy
        assert kwargs["rights_intake_material"] is rights
        return GlobalOptOutPublicMaterial(store=store, authority=public_authority)

    app.state.global_opt_out_public_material_factory = factory
    app.state.global_opt_out_enabled_probe = lambda tenant_id: tenant_id == "alpha"
    router = APIRouter(prefix="/api/v1/public/consent")
    attach_consent_global_opt_out_public_routes(router, dependencies)
    app.include_router(router)
    return app, public_authority


def test_public_adapter_has_closed_get_and_digest_only_submit_contract():
    store = _Store()
    app, public_authority = _app(store)
    client = TestClient(app, base_url="http://127.0.0.1")
    configured = client.get("/api/v1/public/consent/global-opt-out/configuration")
    assert configured.status_code == 200
    assert configured.headers["cache-control"] == "no-store, private"
    assert configured.json()["schema"] == goo.PUBLIC_CONFIG_SCHEMA

    submitted = client.post(
        "/api/v1/public/consent/global-opt-out/requests",
        json={
            "configuration_version": 2,
            "configuration_sha256": "a" * 64,
            "authority_revision": 4,
            "authority_sha256": "b" * 64,
            "idempotency_key": "public-opt-out-one",
        },
    )
    assert submitted.status_code == 201
    assert submitted.json()["state"] == "submitted"
    assert store.calls[0] == ("get", public_authority)
    assert store.calls[1][0:2] == ("submit", public_authority)
    assert set(store.calls[1][2]) == {
        "configuration_version",
        "configuration_sha256",
        "authority_revision",
        "authority_sha256",
        "idempotency_key",
    }

    extra = client.post(
        "/api/v1/public/consent/global-opt-out/requests",
        json={
            "configuration_version": 2,
            "configuration_sha256": "a" * 64,
            "authority_revision": 4,
            "authority_sha256": "b" * 64,
            "idempotency_key": "public-opt-out-two",
            "tenant_id": "alpha",
        },
    )
    assert extra.status_code == 422


@pytest.mark.parametrize(
    ("error", "status", "code"),
    (
        (goo.GlobalOptOutDisabled("disabled"), 404, "global_opt_out_disabled"),
        (
            goo.GlobalOptOutNotConfigured("not configured"),
            404,
            "global_opt_out_not_configured",
        ),
        (
            goo.GlobalOptOutAuthorityStale("stale"),
            409,
            "global_opt_out_authority_stale",
        ),
        (
            goo.GlobalOptOutDSARUnavailable("DSAR unavailable"),
            503,
            "global_opt_out_dsar_unavailable",
        ),
    ),
)
def test_public_adapter_returns_explicit_closed_errors(error, status, code):
    store = _Store()
    store.error = error
    app, _authority = _app(store)
    response = TestClient(app, base_url="http://127.0.0.1").get(
        "/api/v1/public/consent/global-opt-out/configuration"
    )
    assert response.status_code == status
    assert response.json()["detail"]["code"] == code


def test_parent_preflight_hook_is_exact():
    assert global_opt_out_preflight_contracts() == {
        "global-opt-out/configuration": {"GET"},
        "global-opt-out/requests": {"POST"},
    }


def test_public_adapter_checks_nested_gate_before_material_resolution():
    store = _Store()
    app, _authority = _app(store)
    app.state.global_opt_out_enabled_probe = lambda _tenant: False
    response = TestClient(app, base_url="http://127.0.0.1").get(
        "/api/v1/public/consent/global-opt-out/configuration"
    )
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "global_opt_out_disabled"
    assert store.calls == []
