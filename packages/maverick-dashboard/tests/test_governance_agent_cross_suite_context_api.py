from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick import governance_agent_context as context
from maverick_dashboard import governance_agent_cross_suite_context_api as api

API = "/api/v1/governance-agents/context"


class Projection:
    def public_manifest(self):
        return {
            "schema": context.PROJECTION_SCHEMA,
            "tenant_sha256": "a" * 64,
            "agent_kind": "breach_response",
            "complete": True,
            "sources": [],
            "references": [],
            "raw_context_returned": False,
            "external_writes_performed": False,
        }


@pytest.fixture
def environment(monkeypatch: pytest.MonkeyPatch):
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(
        api,
        "require_permission",
        lambda _request, permission: calls.append(("tenant", permission)),
    )
    monkeypatch.setattr(
        api,
        "require_global_permission",
        lambda _request, permission: calls.append(("global", permission)),
    )
    app = FastAPI()
    app.state.governance_agent_cross_suite_preview_resolver = (
        lambda tenant, kind: (
            Projection()
            if tenant == "tenant-a" and kind == "breach_response"
            else (_ for _ in ()).throw(AssertionError("unexpected binding"))
        )
    )
    app.state.governance_agent_cross_suite_readiness = lambda tenant: {
        "tenant": tenant,
        "ready": True,
        "raw_context_persisted": False,
    }
    app.state.governance_agent_cross_suite_maintenance = lambda tenant: {
        "tenant": tenant,
        "double_read_stability_verified": True,
    }
    app.state.governance_agent_cross_suite_recovery = lambda tenant: {
        "tenant": tenant,
        "recovery_mode": "stateless_recapture",
        "stale_previews_reused": False,
    }
    app.include_router(api.router, prefix="/api/v1")
    return (
        TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}),
        calls,
        app,
    )


def test_preview_returns_only_metadata_and_exact_server_references(environment) -> None:
    client, calls, _app = environment
    response = client.get(f"{API}/preview/breach_response")
    assert response.status_code == 200
    assert response.json()["raw_context_returned"] is False
    assert response.json()["external_writes_performed"] is False
    assert calls == [("tenant", "view")]


def test_status_integrity_and_recovery_use_separate_permissions(environment) -> None:
    client, calls, _app = environment
    assert client.get(f"{API}/status").json()["ready"] is True
    assert (
        client.get(f"{API}/integrity").json()["double_read_stability_verified"]
        is True
    )
    recovered = client.post(
        f"{API}/recovery",
        json={"confirm_stateless_recapture": True},
    )
    assert recovered.status_code == 200
    assert recovered.json()["stale_previews_reused"] is False
    assert calls == [
        ("tenant", "view"),
        ("global", "audit"),
        ("global", "admin"),
    ]


def test_recovery_requires_explicit_true_confirmation(environment) -> None:
    client, _calls, _app = environment
    response = client.post(
        f"{API}/recovery",
        json={"confirm_stateless_recapture": False},
    )
    assert response.status_code == 422


def test_projection_conflicts_and_config_failures_map_without_leaking(environment) -> None:
    client, _calls, app = environment
    app.state.governance_agent_cross_suite_preview_resolver = (
        lambda _tenant, _kind: (_ for _ in ()).throw(
            context.GovernanceContextProjectionConflict("source changed")
        )
    )
    assert client.get(f"{API}/preview/breach_response").status_code == 409

    app.state.governance_agent_cross_suite_preview_resolver = (
        lambda _tenant, _kind: (_ for _ in ()).throw(
            context.GovernanceContextProjectionConfigError("disabled")
        )
    )
    response = client.get(f"{API}/preview/breach_response")
    assert response.status_code == 403
    assert response.json()["detail"] == "disabled"


def test_missing_composition_and_unknown_agent_fail_closed(environment) -> None:
    client, _calls, app = environment
    app.state.governance_agent_cross_suite_preview_resolver = None
    response = client.get(f"{API}/preview/breach_response")
    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"]
    unknown = client.get(f"{API}/preview/not-an-agent")
    assert unknown.status_code == 422
