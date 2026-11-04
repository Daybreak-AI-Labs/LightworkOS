from __future__ import annotations

import hashlib
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import privacy_rights_consumer_delivery as delivery
from maverick_dashboard import privacy_rights_consumer_delivery_api as api

API = "/api/v1/privacy/rights-consumer-delivery"
NOW = 2_100_000_000.0
SUBJECT_BINDING = hashlib.sha256(b"consumer:tenant-a").hexdigest()
CAPABILITY = "lwrcd1." + "c" * 43


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "factory_calls": [],
        "permission_calls": [],
    }
    database = tmp_path / "rights-consumer-delivery.sqlite3"

    def require_enabled() -> None:
        if not state["enabled"]:
            raise delivery.RightsConsumerDeliveryConfigError("disabled for test")

    def tenant_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("tenant", permission))

    def global_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("global", permission))

    def authority(tenant_id: str, case_id: str, package_id: str):
        return delivery.ResolvedRightsDeliveryAuthority(
            tenant_id=tenant_id,
            case_id=case_id,
            package_id=package_id,
            consumer_subject_binding_sha256=SUBJECT_BINDING,
            case_revision=8,
            case_record_sha256="a" * 64,
            package_revision=1,
            package_record_sha256="b" * 64,
            identity_status="verified",
            identity_evidence_sha256="d" * 64,
            completeness_ready=True,
            redaction_ready=True,
            closure_ready=True,
            delivery_object_ref_sha256="e" * 64,
            package_sha256="f" * 64,
            package_expires_at=NOW + 600,
            case_retained_until=NOW + 1_200,
            orchestration_delivery_performed=False,
        )

    monkeypatch.setattr(delivery, "require_enabled", require_enabled)
    monkeypatch.setattr(delivery, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        subject = request.headers.get("X-Test-Subject", "delivery-operator")
        request.state.principal = SimpleNamespace(principal=f"user:{subject}")
        return await call_next(request)

    def store_factory(**kwargs):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(kwargs)
        return delivery.RightsConsumerDeliveryStore(
            database,
            authorization_resolver=authority,
            current_consumer_binding_resolver=lambda: SUBJECT_BINDING,
            config_gate=lambda: None,
            principal_resolver=kwargs["principal_resolver"],
            digest_key_resolver=lambda _tenant: b"d" * 32,
            signing_key_resolver=lambda _tenant, _key_ref: b"s" * 32,
            clock=lambda: NOW,
            capability_factory=lambda: CAPABILITY,
            server_grant_factory=lambda: "lwrcg1." + "g" * 43,
        )

    app.state.privacy_rights_consumer_delivery_store_factory = store_factory
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "delivery-operator"},
    )
    return client, database, state


def _mint_body(**changes) -> dict:
    body = {
        "case_id": "case:access",
        "package_id": "package:access",
        "reauthentication_receipt_sha256": "9" * 64,
        "ttl_seconds": 60,
        "retained_until": NOW + 500,
        "max_attempts": 3,
        "min_attempt_interval_seconds": 0,
        "idempotency_key": "mint:delivery-one",
    }
    body.update(changes)
    return body


def _mint(client: TestClient, **changes):
    return client.put(
        f"{API}/deliveries/delivery:one",
        json=_mint_body(**changes),
    )


def test_status_is_store_free_honest_default_private_and_gate_is_closed(environment) -> None:
    client, _database, state = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private"
    status = response.json()
    assert status["enabled"] is True
    assert status["network_io"] is False
    assert status["provider_writes"] is False
    assert status["object_bytes_returned"] is False
    assert status["object_store_credentials_returned"] is False
    assert status["raw_capabilities_persisted"] is False
    assert status["raw_capability_returned_only_on_initial_mint"] is True
    assert status["capability_list_or_replay_endpoint_exposed"] is False
    assert status["public_consumer_endpoint_exposed"] is False
    assert status["consumer_binding_selector_accepted"] is False
    assert status["status_request_opens_tenant_storage"] is False
    assert state["factory_calls"] == []

    state["enabled"] = False
    assert client.get(f"{API}/status").json()["enabled"] is False
    assert _mint(client).status_code == 403
    assert state["factory_calls"] == []


def test_mint_returns_raw_capability_once_and_never_gets_or_replays_it(environment) -> None:
    client, database, state = environment
    first = _mint(client)
    assert first.status_code == 200, first.text
    assert first.headers["cache-control"] == "no-store, private"
    minted = first.json()
    assert minted["capability"] == CAPABILITY
    assert minted["capability_returned"] is True
    assert minted["idempotent_replay"] is False
    assert minted["delivery"]["status"] == "active"
    assert CAPABILITY.encode() not in database.read_bytes()

    replay = _mint(client)
    assert replay.status_code == 200, replay.text
    assert replay.json()["capability"] is None
    assert replay.json()["capability_returned"] is False
    assert replay.json()["idempotent_replay"] is True
    assert CAPABILITY not in replay.text

    fetched = client.get(f"{API}/deliveries/delivery:one")
    assert fetched.status_code == 200, fetched.text
    assert CAPABILITY not in fetched.text
    assert "capability" not in fetched.json()
    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    expected_principal = (
        "prcd-principal-"
        + hashlib.sha256(
            b"lightwork.privacy-rights-consumer-delivery.identity.v1:tenant-a:user:delivery-operator"
        ).hexdigest()[:32]
    )
    assert calls[-1]["tenant_id"] == "tenant-a"
    assert calls[-1]["principal_ref"] == expected_principal
    assert calls[-1]["principal_resolver"]() == expected_principal


@pytest.mark.parametrize(
    "field",
    [
        "tenant",
        "tenant_id",
        "actor",
        "principal",
        "consumer_subject_binding_sha256",
        "capability",
        "object_ref",
        "encryption_key",
    ],
)
def test_mint_rejects_authority_or_secret_spoofing_without_echo(environment, field) -> None:
    client, _database, state = environment
    secret = "raw-private-value-never-echo"
    response = _mint(client, **{field: secret})
    assert response.status_code == 422
    assert response.json()["detail"] == "privacy-rights delivery request body is invalid"
    assert secret not in response.text
    assert state["factory_calls"] == []


def test_revoke_signed_export_get_integrity_and_permissions(environment) -> None:
    client, _database, state = environment
    minted = _mint(client).json()["delivery"]
    exported = client.put(
        f"{API}/deliveries/delivery:one/exports/export:one",
        json={
            "expected_delivery_revision": minted["revision"],
            "signing_key_ref": "env:RIGHTS_DELIVERY_SIGNING_KEY",
            "retained_until": NOW + 400,
            "idempotency_key": "export:delivery-one",
        },
    )
    assert exported.status_code == 200, exported.text
    assert exported.json()["schema"] == delivery.EXPORT_SCHEMA
    assert CAPABILITY not in exported.text
    assert exported.json()["body"]["limitations"]["object_bytes_returned"] is False
    fetched_export = client.get(f"{API}/exports/export:one")
    assert fetched_export.status_code == 200, fetched_export.text
    assert fetched_export.json()["body_sha256"] == exported.json()["body_sha256"]

    revoked = client.post(
        f"{API}/deliveries/delivery:one/revoke",
        json={
            "reason_code": "operator_revoked",
            "expected_revision": minted["revision"],
            "idempotency_key": "revoke:delivery-one",
        },
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["revision"] == minted["revision"] + 1
    integrity = client.get(f"{API}/integrity")
    assert integrity.status_code == 200, integrity.text
    assert integrity.json()["valid"] is True
    assert integrity.json()["verified_records"] > 0

    calls = state["permission_calls"]
    assert isinstance(calls, list)
    assert ("global", "admin") in calls
    assert ("tenant", "operate") in calls
    assert ("global", "audit") in calls


def test_tenant_isolation_generic_errors_and_no_consumer_or_list_routes(environment) -> None:
    client, _database, state = environment
    assert _mint(client).status_code == 200
    state["tenant"] = "tenant-b"
    missing = client.get(f"{API}/deliveries/delivery:one")
    assert missing.status_code == 404
    assert missing.json()["detail"] == "privacy-rights delivery record was not found"
    assert client.get(f"{API}/deliveries").status_code == 404
    assert client.post(f"{API}/redeem", json={"capability": CAPABILITY}).status_code == 404
    assert client.post(f"{API}/grants/claim", json={"server_grant": "x"}).status_code == 404


def test_default_store_fails_closed_without_every_trusted_runtime_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(delivery, "require_enabled", lambda: None)
    monkeypatch.setattr(delivery, "enabled", lambda: True)
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "require_global_permission", lambda _request, _permission: None)
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:operator")
        return await call_next(request)

    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.put(
        f"{API}/deliveries/delivery:one",
        json=_mint_body(),
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "privacy-rights delivery authority is unavailable"


def test_tenant_local_default_opens_only_with_all_trusted_resolvers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick import paths

    monkeypatch.setattr(delivery, "require_enabled", lambda: None)
    monkeypatch.setattr(delivery, "enabled", lambda: True)
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "require_global_permission", lambda _request, _permission: None)
    database = tmp_path / "tenant-local-delivery.sqlite3"
    monkeypatch.setattr(paths, "data_dir", lambda *_parts, **_kwargs: database)
    factory_contexts: list[dict] = []
    current = time.time()

    def authority_factory(**context):
        factory_contexts.append(context)

        def resolve(tenant_id: str, case_id: str, package_id: str):
            return delivery.ResolvedRightsDeliveryAuthority(
                tenant_id=tenant_id,
                case_id=case_id,
                package_id=package_id,
                consumer_subject_binding_sha256=SUBJECT_BINDING,
                case_revision=8,
                case_record_sha256="a" * 64,
                package_revision=1,
                package_record_sha256="b" * 64,
                identity_status="verified",
                identity_evidence_sha256="d" * 64,
                completeness_ready=True,
                redaction_ready=True,
                closure_ready=True,
                delivery_object_ref_sha256="e" * 64,
                package_sha256="f" * 64,
                package_expires_at=current + 600,
                case_retained_until=current + 1_200,
                orchestration_delivery_performed=False,
            )

        return resolve

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:operator")
        return await call_next(request)

    app.state.privacy_rights_consumer_delivery_authorization_resolver_factory = authority_factory
    app.state.privacy_rights_consumer_delivery_binding_resolver_factory = lambda **_context: (
        lambda: SUBJECT_BINDING
    )
    app.state.privacy_rights_consumer_delivery_digest_key_resolver = lambda _tenant: b"d" * 32
    app.state.privacy_rights_consumer_delivery_signing_key_resolver = lambda _tenant, _ref: (
        b"s" * 32
    )
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.put(
        f"{API}/deliveries/delivery:local",
        json=_mint_body(retained_until=current + 500),
    )
    assert response.status_code == 200, response.text
    assert response.json()["capability_returned"] is True
    assert response.json()["capability"].startswith("lwrcd1.")
    assert database.exists()
    assert factory_contexts[0]["tenant_id"] == "tenant-a"
    assert factory_contexts[0]["principal_ref"].startswith("prcd-principal-")


def test_openapi_contract_has_only_operator_metadata_lifecycle_routes(environment) -> None:
    client, _database, _state = environment
    paths = set(client.app.openapi()["paths"])
    assert f"{API}/deliveries/{{delivery_id}}" in paths
    assert f"{API}/deliveries/{{delivery_id}}/revoke" in paths
    assert f"{API}/deliveries/{{delivery_id}}/exports/{{export_id}}" in paths
    assert f"{API}/exports/{{export_id}}" in paths
    assert f"{API}/retention/purge" in paths
    assert f"{API}/integrity" in paths
    assert not any("redeem" in path or "claim" in path for path in paths)


def test_evidence_record_uses_the_deployment_key_and_current_link_version(environment) -> None:
    client, _database, state = environment
    assert _mint(client).status_code == 200
    record = client.post(
        f"{API}/deliveries/delivery:one/evidence-record",
        json={"idempotency_key": "evidence-1"},
    )
    assert record.status_code == 200, record.text
    assert record.json()["signing_key_ref"] == api.DEFAULT_EVIDENCE_SIGNING_KEY_REF
    assert CAPABILITY not in record.text
    assert ("tenant", "operate") in state["permission_calls"]
    assert client.post(
        f"{API}/deliveries/delivery:missing/evidence-record",
        json={"idempotency_key": "evidence-2"},
    ).status_code == 404
