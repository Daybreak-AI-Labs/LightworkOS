from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import third_party_intelligence as intelligence
from maverick.paths import tenant_scope
from maverick_dashboard import third_party_intelligence_api as api
from maverick_dashboard.third_party_intelligence_provider_composition import (
    TenantThirdPartyProviderRuntime,
    ThirdPartyProviderCompositionError,
    attach_third_party_intelligence_provider_composition,
    provider_settings,
)

TENANT = "tenant-provider-runtime"
CONFIG = {
    "third_party_management": {
        "enable": True,
        "intelligence": {
            "enable": True,
            "providers": {
                "enable": True,
                "enabled_providers": [
                    "supplywisdom",
                    "iss_corporate_solutions",
                ],
                "supplywisdom_host": "tenant.supplywisdom.example",
                "iss_corporate_solutions_host": (
                    "tenant.iss-corporate-solutions.example"
                ),
                "timeout_seconds": 20,
                "scheduler": {"enable": False, "poll_seconds": 900},
            },
        },
    }
}


def _approved_source(
    store: intelligence.ThirdPartyIntelligenceStore,
    *,
    provider: str,
    source_id: str,
    host: str,
    credential: str,
    kind: str,
):
    pending = store.enroll_source(
        TENANT,
        source_id=source_id,
        provider=provider,
        kind=kind,
        provenance_uri=f"https://{host}/licensed-source",
        credential_env=credential,
        license_ref=f"license-{provider}",
        rights_basis="Approved bounded monitoring use.",
        purposes=("monitoring",),
        territories=("US",),
        retention_seconds=86_400,
        actor_ref="source-owner",
        idempotency_key=f"enroll-{source_id}",
    )
    return store.approve_source(
        TENANT,
        source_id,
        expected_revision=pending.revision,
        approver_ref="source-reviewer",
        approved=True,
        rationale="License, purpose, territory, and retention were independently reviewed.",
        idempotency_key=f"approve-{source_id}",
    )


@pytest.fixture()
def composed(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", TENANT)
    store = intelligence.ThirdPartyIntelligenceStore(
        tmp_path / "third-party-intelligence.sqlite3",
        config_gate=lambda: None,
    )
    supply = _approved_source(
        store,
        provider="supplywisdom",
        source_id="source-supplywisdom",
        host="tenant.supplywisdom.example",
        credential="SUPPLYWISDOM_TOKEN",
        kind="cyber_posture",
    )
    iss = _approved_source(
        store,
        provider="iss_corporate_solutions",
        source_id="source-iss",
        host="tenant.iss-corporate-solutions.example",
        credential="ISS_CORPORATE_SOLUTIONS_TOKEN",
        kind="performance",
    )
    secrets = {
        "SUPPLYWISDOM_TOKEN": "supply-token-123",
        "ISS_CORPORATE_SOLUTIONS_TOKEN": "iss-token-123456",
    }
    runtime = TenantThirdPartyProviderRuntime(
        intelligence_store_for=lambda tenant, _request: (
            store if tenant == TENANT else None
        ),
        runtime_store_for=lambda _tenant: object(),
        config_loader=lambda tenant: CONFIG if tenant == TENANT else {},
        secret_resolver=secrets.get,
    )
    return runtime, store, supply, iss


def test_closed_settings_and_readiness_do_not_claim_live_acceptance(composed) -> None:
    runtime, _store, supply, _iss = composed
    settings = provider_settings(CONFIG)
    assert settings is not None
    assert settings.enabled_providers == (
        "supplywisdom",
        "iss_corporate_solutions",
    )

    with tenant_scope(tenant=TENANT):
        readiness = runtime.readiness(TENANT)
        source = runtime.source_readiness(
            TENANT,
            supply.source_id,
            verify_secret=True,
        )

    assert readiness["configured"] is True
    assert readiness["configuration_ready"] is True
    assert readiness["ready"] is False
    assert readiness["transport_hardened"] is True
    assert readiness["resolved_endpoint_count"] == 2
    assert readiness["endpoint_authorities_returned"] is False
    assert "resolved_endpoints" not in readiness
    assert readiness["licensed_provider_credential_verified"] is False
    assert readiness["live_provider_acceptance_verified"] is False
    assert source["ready_for_provider_attempt"] is True
    assert source["provider_network_io"] is False
    assert source["live_provider_acceptance_verified"] is False
    assert "supply-token-123" not in repr(readiness)
    assert "supply-token-123" not in repr(source)


def test_revocation_is_reloaded_before_credential_readiness(composed) -> None:
    runtime, store, supply, _iss = composed
    store.revoke_source(
        TENANT,
        supply.source_id,
        expected_revision=supply.revision,
        actor_ref="source-reviewer",
        rationale="Licensed credential authority was revoked.",
        idempotency_key="revoke-source-supplywisdom",
    )

    with tenant_scope(tenant=TENANT):
        result = runtime.source_readiness(
            TENANT,
            supply.source_id,
            verify_secret=True,
        )

    assert result["ready"] is False
    assert result["ready_for_provider_attempt"] is False
    assert result["error_code"] == "credential_revoked"
    assert result["provider_network_io"] is False


def test_malformed_host_binding_fails_before_store_or_secret_access(composed) -> None:
    runtime, _store, _supply, _iss = composed
    malformed = {
        **CONFIG,
        "third_party_management": {
            **CONFIG["third_party_management"],
            "intelligence": {
                **CONFIG["third_party_management"]["intelligence"],
                "providers": {
                    **CONFIG["third_party_management"]["intelligence"]["providers"],
                    "supplywisdom_host": "https://attacker.example/path",
                },
            },
        },
    }
    runtime._config_loader = lambda _tenant: malformed

    with tenant_scope(tenant=TENANT), pytest.raises(
        ThirdPartyProviderCompositionError,
        match="provider_configuration_invalid",
    ):
        runtime.readiness(TENANT)


def test_api_exposes_side_effect_free_status_and_admin_source_check(
    composed,
    monkeypatch,
) -> None:
    runtime, _store, supply, _iss = composed
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(
        api,
        "require_global_permission",
        lambda _request, _permission: None,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(sub="provider-admin")
        return await call_next(request)

    app.state.third_party_intelligence_provider_runtime = runtime
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    status = client.get("/api/v1/third-party/intelligence/provider-runtime/status")
    assert status.status_code == 200, status.text
    assert status.json()["status_secret_resolution"] is False
    assert status.json()["status_provider_network_io"] is False
    assert status.json()["scheduler"]["running"] is False

    checked = client.post(
        "/api/v1/third-party/intelligence/provider-runtime/sources/"
        f"{supply.source_id}/readiness",
        json={},
    )
    assert checked.status_code == 200, checked.text
    assert checked.json()["ready_for_provider_attempt"] is True
    assert checked.json()["provider_network_io"] is False


def test_lifespan_attachment_starts_and_stops_the_feed_scheduler() -> None:
    class Scheduler:
        def __init__(self) -> None:
            self.started = False
            self.stopped = False

        def start(self) -> bool:
            self.started = True
            return True

        def stop(self, *, timeout: float = 5.0) -> bool:
            assert timeout == 5.0
            self.stopped = True
            return True

        def status(self):
            return {"running": self.started and not self.stopped}

    scheduler = Scheduler()
    runtime = TenantThirdPartyProviderRuntime(
        intelligence_store_for=lambda _tenant, _request: object(),
        runtime_store_for=lambda _tenant: object(),
        config_loader=lambda _tenant: {},
        scheduler=scheduler,  # type: ignore[arg-type]
    )
    app = FastAPI()
    attached = attach_third_party_intelligence_provider_composition(
        app,
        runtime=runtime,
    )
    assert attached is runtime
    assert app.state.third_party_intelligence_provider_runtime is runtime
    assert app.state.third_party_intelligence_feed_scheduler is scheduler

    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/openapi.json").status_code == 200
        assert scheduler.started is True
        assert scheduler.stopped is False

    assert scheduler.stopped is True
