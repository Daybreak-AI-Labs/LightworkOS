from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import consent_profile_data as profile_data
from maverick_dashboard import consent_profile_data_api as api

API = "/api/v1/consent/profile-data"
NOW = 1_800_000_000.0
DAY = 86_400


@dataclass
class Clock:
    now: float = NOW

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, Any] = {
        "enabled": True,
        "tenant": "tenant-a",
        "factory_calls": [],
        "permission_calls": [],
    }
    clock = Clock()
    database = tmp_path / "consent-profile-data.sqlite3"
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setattr(api, "_tenant_id", lambda: state["tenant"])

    def tenant_permission(_request: Request, permission: str) -> None:
        state["permission_calls"].append(("tenant", permission))

    def global_permission(_request: Request, permission: str) -> None:
        state["permission_calls"].append(("global", permission))

    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)

    def store_for(tenant_id: str, principal_ref: str) -> profile_data.ConsentProfileDataStore:
        state["factory_calls"].append((tenant_id, principal_ref))
        return profile_data.ConsentProfileDataStore(
            database,
            config_gate=lambda: None,
            principal_resolver=lambda: principal_ref,
            clock=clock,
        )

    dependencies = api.ConsentProfileDataAdminDependencies(
        gate=lambda: state["enabled"],
        store_for=store_for,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            principal=("user:" + request.headers.get("X-Test-Subject", "profile-owner"))
        )
        return await call_next(request)

    app.include_router(api.create_consent_profile_data_router(dependencies), prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "profile-owner"},
    )
    return client, state, clock, database


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _catalog(*, idempotency_key: str = "catalog-create-v1") -> dict[str, Any]:
    return {
        "catalog_id": "consumer-profile-v1",
        "property_id": "web-main",
        "publication_sha256": _digest("publication"),
        "bundle_sha256": _digest("bundle"),
        "configuration_sha256": _digest("configuration"),
        "policy_id": "consent-policy",
        "policy_version": 1,
        "policy_sha256": _digest("policy"),
        "definitions": [
            {
                "preference_id": "required-bool",
                "definition_version": 1,
                "label_ref": "required-bool",
                "value_type": "boolean",
                "options": [],
                "required": True,
                "expires_after_seconds": None,
                "retention_seconds": DAY,
            },
            {
                "preference_id": "locale",
                "definition_version": 1,
                "label_ref": "locale",
                "value_type": "single_select",
                "options": [
                    {"value_id": "eu", "label_ref": "eu"},
                    {"value_id": "us", "label_ref": "us"},
                ],
                "required": False,
                "expires_after_seconds": None,
                "retention_seconds": DAY,
            },
        ],
        "retention_seconds": DAY,
        "expected_latest_version": 0,
        "idempotency_key": idempotency_key,
    }


def _journey(
    *,
    journey_id: str = "progressive-profile-v1",
    idempotency_key: str = "journey-create-v1",
) -> dict[str, Any]:
    return {
        "journey_id": journey_id,
        "catalog_id": "consumer-profile-v1",
        "catalog_version": 1,
        "stages": [
            {
                "stage_id": "foundation",
                "priority": 10,
                "prompt_label_ref": "foundation",
                "preference_ids": ["required-bool", "locale"],
                "condition": None,
            },
            {
                "stage_id": "analytics-follow-up",
                "priority": 20,
                "prompt_label_ref": "analytics-follow-up",
                "preference_ids": ["locale"],
                "condition": {
                    "source": "purpose",
                    "key": "analytics",
                    "operator": "equals",
                    "value": "grant",
                },
            },
        ],
        "max_prompts": 2,
        "cooldown_seconds": 60,
        "frequency_cap": 3,
        "frequency_window_seconds": 600,
        "retention_seconds": DAY,
        "expected_latest_version": 0,
        "idempotency_key": idempotency_key,
    }


def _ok(response, expected: int = 200) -> dict[str, Any]:
    assert response.status_code == expected, response.text
    return response.json()


def _create_and_approve_catalog(client: TestClient) -> tuple[dict[str, Any], dict[str, Any]]:
    created = _ok(client.post(f"{API}/catalogs", json=_catalog()), 201)
    approved = _ok(
        client.post(
            f"{API}/catalogs/consumer-profile-v1/versions/1/approve",
            headers={"X-Test-Subject": "privacy-reviewer"},
            json={
                "expected_revision": 1,
                "idempotency_key": "catalog-approve-v1",
            },
        )
    )
    return created, approved


def test_status_gate_exact_tenant_and_stable_derived_principal(environment) -> None:
    client, state, _clock, _database = environment
    status = _ok(client.get(f"{API}/status"))
    assert status["enabled"] is True
    assert status["tenant_id"] == "tenant-a"
    assert status["product_boundaries"] == {
        "provider_neutral": True,
        "network_io": False,
        "live_traffic_operated": False,
        "accessibility_acceptance_verified": False,
        "customer_acceptance_verified": False,
        "protected_trait_inference": False,
        "raw_pii_persisted": False,
        "raw_profile_capability_persisted": False,
    }
    expected = (
        "admin-"
        + hashlib.sha256(b"consent-profile-data\0tenant-a\0user:profile-owner").hexdigest()[:48]
    )
    assert state["factory_calls"][-1] == ("tenant-a", expected)
    assert "profile-owner" not in str(status)

    state["enabled"] = False
    denied = client.get(f"{API}/status")
    assert denied.status_code == 403
    assert "profile_data" in denied.json()["detail"]
    state["enabled"] = True
    state["tenant"] = "Café Customer 北"
    unicode_status = _ok(client.get(f"{API}/status"))
    assert unicode_status["tenant_id"] == "Café Customer 北"


def test_catalog_four_eyes_idempotency_cas_and_tenant_isolation(environment) -> None:
    client, state, _clock, _database = environment
    created = _ok(client.post(f"{API}/catalogs", json=_catalog()), 201)
    assert created["state"] == "pending_approval"
    assert created["revision"] == 1
    assert "profile-owner" not in str(created)
    assert _ok(client.post(f"{API}/catalogs", json=_catalog()), 201) == created

    same_actor = client.post(
        f"{API}/catalogs/consumer-profile-v1/versions/1/approve",
        json={"expected_revision": 1, "idempotency_key": "catalog-self-approve"},
    )
    assert same_actor.status_code == 403
    assert "cannot approve" in same_actor.json()["detail"]
    approved = _ok(
        client.post(
            f"{API}/catalogs/consumer-profile-v1/versions/1/approve",
            headers={"X-Test-Subject": "privacy-reviewer"},
            json={"expected_revision": 1, "idempotency_key": "catalog-approve-v1"},
        )
    )
    assert approved["state"] == "published"
    assert approved["revision"] == 2
    assert approved["created_by"] != approved["approved_by"]
    stale = client.post(
        f"{API}/catalogs/consumer-profile-v1/versions/1/approve",
        headers={"X-Test-Subject": "another-reviewer"},
        json={"expected_revision": 1, "idempotency_key": "catalog-stale-v1"},
    )
    assert stale.status_code == 409
    loaded = _ok(client.get(f"{API}/catalogs/consumer-profile-v1/versions/1"))
    assert loaded["integrity_sha256"] == approved["integrity_sha256"]

    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/catalogs/consumer-profile-v1/versions/1").status_code == 404
    state["tenant"] = "tenant-a"


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "tenant-b"),
        ("tenant", "tenant-b"),
        ("actor", "attacker"),
        ("principal", "attacker"),
        ("profile_id", "victim"),
        ("profile_capability", "raw-secret-capability"),
        ("profile_capability_sha256", "a" * 64),
        ("key_material", "raw-encryption-key"),
        ("email", "person@example.test"),
    ],
)
def test_strict_catalog_body_has_no_authority_or_pii_selectors(
    environment,
    field: str,
    value: str,
) -> None:
    client, _state, _clock, _database = environment
    response = client.post(f"{API}/catalogs", json={**_catalog(), field: value})
    assert response.status_code == 422


def test_closed_schema_rejects_type_coercion_unknown_fields_and_code(environment) -> None:
    client, _state, _clock, _database = environment
    coerced = _catalog()
    coerced["expected_latest_version"] = "0"
    assert client.post(f"{API}/catalogs", json=coerced).status_code == 422
    free_text = _catalog()
    free_text["definitions"][1]["value_type"] = "free_text"
    assert client.post(f"{API}/catalogs", json=free_text).status_code == 422
    unknown = _catalog()
    unknown["definitions"][0]["schema"] = {"type": "object"}
    assert client.post(f"{API}/catalogs", json=unknown).status_code == 422

    _create_and_approve_catalog(client)
    executable = _journey()
    executable["stages"][0]["condition"] = {
        "source": "preference",
        "key": "locale",
        "operator": "equals",
        "value": "eu",
        "code": "return process.env",
    }
    assert client.post(f"{API}/journeys", json=executable).status_code == 422
    unsupported_value = _journey(idempotency_key="journey-unsupported-value")
    unsupported_value["stages"][1]["condition"]["value"] = "<script>alert(1)</script>"
    assert client.post(f"{API}/journeys", json=unsupported_value).status_code == 422


def test_journey_four_eyes_and_every_lifecycle_method(environment) -> None:
    client, _state, _clock, _database = environment
    _create_and_approve_catalog(client)
    created = _ok(client.post(f"{API}/journeys", json=_journey()), 201)
    assert created["state"] == "draft"
    assert created["revision"] == 1
    self_approval = client.post(
        f"{API}/journeys/progressive-profile-v1/versions/1/approve",
        json={"expected_revision": 1, "idempotency_key": "journey-self-approve"},
    )
    assert self_approval.status_code == 403
    approved = _ok(
        client.post(
            f"{API}/journeys/progressive-profile-v1/versions/1/approve",
            headers={"X-Test-Subject": "journey-reviewer"},
            json={"expected_revision": 1, "idempotency_key": "journey-approve-v1"},
        )
    )
    assert approved["state"] == "approved"
    active = _ok(
        client.post(
            f"{API}/journeys/progressive-profile-v1/versions/1/activate",
            json={"expected_revision": 2, "idempotency_key": "journey-activate-v1"},
        )
    )
    assert active["state"] == "active"
    paused = _ok(
        client.post(
            f"{API}/journeys/progressive-profile-v1/versions/1/pause",
            json={"expected_revision": 3, "idempotency_key": "journey-pause-v1"},
        )
    )
    assert paused["state"] == "paused"
    resumed = _ok(
        client.post(
            f"{API}/journeys/progressive-profile-v1/versions/1/activate",
            json={"expected_revision": 4, "idempotency_key": "journey-resume-v1"},
        )
    )
    assert resumed["state"] == "active"
    rolled_back = _ok(
        client.post(
            f"{API}/journeys/progressive-profile-v1/versions/1/rollback",
            json={"expected_revision": 5, "idempotency_key": "journey-rollback-v1"},
        )
    )
    assert rolled_back["state"] == "rolled_back"
    loaded = _ok(client.get(f"{API}/journeys/progressive-profile-v1/versions/1"))
    assert loaded["revision"] == 6

    kill_body = _journey(
        journey_id="progressive-profile-kill",
        idempotency_key="journey-kill-create",
    )
    assert client.post(f"{API}/journeys", json=kill_body).status_code == 201
    _ok(
        client.post(
            f"{API}/journeys/progressive-profile-kill/versions/1/approve",
            headers={"X-Test-Subject": "journey-reviewer"},
            json={"expected_revision": 1, "idempotency_key": "journey-kill-approve"},
        )
    )
    killed = _ok(
        client.post(
            f"{API}/journeys/progressive-profile-kill/versions/1/kill",
            json={"expected_revision": 2, "idempotency_key": "journey-kill-final"},
        )
    )
    assert killed["state"] == "killed"


def test_permission_floors_main_prefix_integrity_and_retention(environment) -> None:
    client, state, clock, _database = environment
    _create_and_approve_catalog(client)
    _ok(client.post(f"{API}/journeys", json=_journey()), 201)
    _ok(client.get(f"{API}/catalogs/consumer-profile-v1/versions/1"))
    _ok(client.get(f"{API}/journeys/progressive-profile-v1/versions/1"))
    integrity = _ok(client.get(f"{API}/integrity"))
    assert integrity["verified_records"] > 0
    clock.now += 2 * DAY
    purge_body = {
        "before": clock.now,
        "idempotency_key": "profile-retention-purge",
    }
    purged = _ok(client.post(f"{API}/retention/purge", json=purge_body))
    assert _ok(client.post(f"{API}/retention/purge", json=purge_body)) == purged
    assert purged["journeys"] == 1
    assert purged["catalogs"] == 1
    assert ("tenant", "operate") in state["permission_calls"]
    assert state["permission_calls"].count(("global", "admin")) >= 4
    assert ("global", "audit") in state["permission_calls"]

    paths = set(client.app.openapi()["paths"])
    assert {
        f"{API}/status",
        f"{API}/catalogs",
        f"{API}/catalogs/{{catalog_id}}/versions/{{version}}",
        f"{API}/catalogs/{{catalog_id}}/versions/{{version}}/approve",
        f"{API}/journeys",
        f"{API}/journeys/{{journey_id}}/versions/{{version}}",
        f"{API}/journeys/{{journey_id}}/versions/{{version}}/approve",
        f"{API}/journeys/{{journey_id}}/versions/{{version}}/activate",
        f"{API}/journeys/{{journey_id}}/versions/{{version}}/pause",
        f"{API}/journeys/{{journey_id}}/versions/{{version}}/kill",
        f"{API}/journeys/{{journey_id}}/versions/{{version}}/rollback",
        f"{API}/retention/purge",
        f"{API}/integrity",
    } <= paths


def test_app_state_factory_receives_exact_tenant_and_resolver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    captured: list[dict[str, Any]] = []
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:factory-owner")
        return await call_next(request)

    def factory(**kwargs):
        captured.append(kwargs)
        return profile_data.ConsentProfileDataStore(
            tmp_path / "factory.sqlite3",
            config_gate=lambda: None,
            principal_resolver=kwargs["principal_resolver"],
        )

    app.state.consent_profile_data_store_factory = factory
    app.include_router(
        api.create_consent_profile_data_router(
            api.ConsentProfileDataAdminDependencies(gate=lambda: True)
        ),
        prefix="/api/v1",
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get(f"{API}/status").status_code == 200
    assert captured[0]["tenant_id"] == "tenant-a"
    assert captured[0]["request"].app is app
    principal_ref = captured[0]["principal_resolver"]()
    assert principal_ref.startswith("admin-")
    assert "factory-owner" not in principal_ref


@pytest.mark.parametrize(
    "failure",
    [
        profile_data.ConsentProfileDataIntegrityError(
            r"corrupt at C:\secret\tenant-a\actor@example.test"
        ),
        RuntimeError(r"unexpected C:\secret\tenant-a\actor@example.test"),
    ],
)
def test_integrity_and_unexpected_failures_are_generic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "require_global_permission", lambda _request, _permission: None)

    class BrokenStore:
        def verify_integrity(self, _tenant_id: str):
            raise failure

    app = FastAPI()
    app.include_router(
        api.create_consent_profile_data_router(
            api.ConsentProfileDataAdminDependencies(
                gate=lambda: True,
                principal_for=lambda _request, _tenant: "admin-test-principal",
                store_for=lambda _tenant, _principal: BrokenStore(),
            )
        ),
        prefix="/api/v1",
    )
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
        raise_server_exceptions=False,
    )
    response = client.get(f"{API}/integrity")
    assert response.status_code == 503
    assert response.json() == {"detail": "consent profile-data authority unavailable"}
    assert "secret" not in response.text
    assert "actor@example" not in response.text


def test_source_has_no_network_or_dynamic_execution_primitives() -> None:
    source = Path(api.__file__).read_text(encoding="utf-8")
    for primitive in (
        "requests.",
        "httpx.",
        "urllib.request",
        "socket.",
        "subprocess.",
        "shell=True",
        "exec(",
    ):
        assert primitive not in source


def test_catalog_and_journey_lists_are_read_only_tenant_scoped_operate_views(environment) -> None:
    client, state, _clock, _database = environment
    _create_and_approve_catalog(client)
    _ok(client.post(f"{API}/journeys", json=_journey()), 201)
    state["permission_calls"].clear()
    catalogs = _ok(client.get(f"{API}/catalogs"))
    journeys = _ok(client.get(f"{API}/journeys"))
    assert [(c["catalog_id"], c["version"], c["state"]) for c in catalogs["items"]] == [
        ("consumer-profile-v1", 1, "published")
    ]
    assert [(j["journey_id"], j["state"]) for j in journeys["items"]] == [
        ("progressive-profile-v1", "draft")
    ]
    assert state["permission_calls"] == [("tenant", "operate"), ("tenant", "operate")]
    state["tenant"] = "tenant-b"
    assert _ok(client.get(f"{API}/catalogs"))["items"] == []
    assert _ok(client.get(f"{API}/journeys"))["items"] == []
    state["tenant"] = "tenant-a"
    state["enabled"] = False
    assert client.get(f"{API}/catalogs").status_code == 403


def test_contract_lookup_needs_operate_and_hides_resolution_failures(
    environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maverick_dashboard import consent_public_admin_api

    client, state, _clock, _database = environment
    monkeypatch.setattr(consent_public_admin_api, "_require_enabled", lambda: None)
    seen: list[tuple] = []

    def contract(tenant, credential_id, **kwargs):
        seen.append((tenant, credential_id, kwargs))
        if credential_id == "gone":
            raise LookupError("no")
        if credential_id == "stale":
            raise ValueError("stale")
        return {"catalog_id": "profile-catalog-x", "questions": []}

    monkeypatch.setattr(api, "published_contract_for_key", contract)
    state["permission_calls"].clear()
    found = _ok(client.get(f"{API}/contract?credential_id=key-1&jurisdiction=eu&country_code=FR&locale=fr-FR"))
    assert found["catalog_id"] == "profile-catalog-x"
    assert seen[0] == ("tenant-a", "key-1", {"jurisdiction": "eu", "country_code": "FR", "locale": "fr-FR"})
    assert state["permission_calls"] == [("tenant", "operate")]
    assert client.get(f"{API}/contract?credential_id=gone").status_code == 404
    assert client.get(f"{API}/contract?credential_id=stale").status_code == 409
    assert client.get(f"{API}/contract?credential_id=bad%20id").status_code == 422
