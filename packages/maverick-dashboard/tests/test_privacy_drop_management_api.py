from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import privacy_drop_management as drop
from maverick_dashboard import privacy_drop_management_api as api

TENANT = "tenant-drop"
DROP_ID = 12345
TEMPLATE_ID = "550e8400-e29b-41d4-a716-446655440000"
NOW = 2_100_000_000.0
BASE = "/api/v1/privacy/drop"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _authority(
    *,
    tenant_id: str = TENANT,
    drop_id: int = DROP_ID,
    request_type: str = "DataDeletion",
    template_id: str = TEMPLATE_ID,
    language: str = "en-us",
) -> drop.DROPRecordAuthority:
    return drop.DROPRecordAuthority(
        tenant_id=tenant_id,
        drop_id=drop_id,
        broker_registration_sha256=_digest("server-broker-binding"),
        subject_binding_sha256=_digest("server-subject-binding"),
        request_type=request_type,
        template_id=template_id,
        language=language,
        record_revision=7,
        valid_until=NOW + 3_600,
    ).normalized()


def _record(
    authority: drop.DROPRecordAuthority,
    *,
    status: str = "PENDING",
) -> drop.DROPRequestRecord:
    terminal = status != "PENDING"
    return drop.DROPRequestRecord(
        tenant_id=authority.tenant_id,
        drop_id=authority.drop_id,
        request_type=authority.request_type,
        status=status,
        revision=2 if terminal else 1,
        request_queue_id="af34084d-10ba-55cd-b10a-3bfcbc691859",
        request_queue_ref_id="SL244HWD6D",
        internal_case_id="drop-case-12345",
        authority_sha256=authority.authority_sha256,
        outcome_evidence_sha256=_digest("outcome") if terminal else "",
        created_at=NOW,
        updated_at=NOW + (10 if terminal else 0),
        retained_until=NOW + 90_000,
        integrity_sha256=_digest(f"record:{status}"),
    )


def _create_body(**updates: object) -> dict[str, object]:
    body: dict[str, object] = {
        "request_type": "DataDeletion",
        "template_id": TEMPLATE_ID,
        "language": "en-US",
        "expected_revision": 0,
        "idempotency_key": "create-drop-12345",
    }
    body.update(updates)
    return body


class Store:
    def __init__(self, state: SimpleNamespace, tenant_id: str = TENANT) -> None:
        self.state = state
        self.tenant_id = tenant_id
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def _result(
        self,
        name: str,
        args: tuple[object, ...],
        kwargs: dict[str, object],
        *,
        status: str = "PENDING",
    ):
        self.calls.append((name, args, kwargs))
        if self.state.store_failure is not None:
            raise self.state.store_failure
        if self.state.record_override is not None:
            return self.state.record_override
        authority = args[0] if args else self.state.last_authority
        return _record(authority, status=status)

    def create_request(self, *args: object, **kwargs: object):
        return self._result("create_request", args, kwargs)

    def update_status(self, *args: object, **kwargs: object):
        return self._result(
            "update_status",
            args,
            kwargs,
            status=str(kwargs["status"]),
        )

    def get_request(self, *args: object, **kwargs: object):
        return self._result("get_request", args, kwargs)

    def verify_integrity(self) -> bool:
        self.calls.append(("verify_integrity", (), {}))
        if self.state.store_failure is not None:
            raise self.state.store_failure
        return self.state.integrity


@pytest.fixture()
def environment(monkeypatch: pytest.MonkeyPatch):
    state = SimpleNamespace(
        tenant=TENANT,
        subject="user:drop-operator",
        enabled=True,
        enabled_calls=[],
        readiness=True,
        readiness_calls=[],
        readiness_failure=None,
        factory_calls=[],
        resolver_calls=[],
        permissions=[],
        authority_mutator=None,
        resolver_failure=None,
        factory_failure=None,
        store_failure=None,
        record_override=None,
        last_authority=_authority(),
        integrity=True,
    )
    monkeypatch.setattr(api, "_tenant_id", lambda: state.tenant)
    monkeypatch.setattr(
        api,
        "require_permission",
        lambda _request, permission: state.permissions.append(permission),
    )
    monkeypatch.setattr(
        api,
        "require_global_permission",
        lambda _request, permission: state.permissions.append(permission),
    )
    store = Store(state)
    state.store = store

    def enabled_probe(tenant_id: str) -> bool:
        state.enabled_calls.append(tenant_id)
        return state.enabled

    def factory(*, tenant_id: str, actor_ref: str, request: Request):
        state.factory_calls.append((tenant_id, actor_ref, request))
        if state.factory_failure is not None:
            raise state.factory_failure
        return state.store

    def readiness_probe(tenant_id: str) -> bool:
        state.readiness_calls.append(tenant_id)
        if state.readiness_failure is not None:
            raise state.readiness_failure
        return state.readiness

    def resolver(**kwargs: object):
        state.resolver_calls.append(kwargs)
        if state.resolver_failure is not None:
            raise state.resolver_failure
        authority = _authority(
            tenant_id=str(kwargs["tenant_id"]),
            drop_id=int(kwargs["drop_id"]),
            request_type=str(kwargs["request_type"] or "DataDeletion"),
            template_id=str(kwargs["template_id"] or TEMPLATE_ID),
            language=str(kwargs["language"] or "en-us"),
        )
        if state.authority_mutator is not None:
            authority = state.authority_mutator(authority)
        state.last_authority = authority
        return authority

    deps = api.DROPManagementDependencies(
        store_factory=factory,
        authority_resolver=resolver,
        enabled_probe=enabled_probe,
        readiness_probe=readiness_probe,
    )
    app = FastAPI()

    @app.middleware("http")
    async def install_principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(sub=state.subject)
        return await call_next(request)

    app.include_router(api.create_privacy_drop_management_router(deps), prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    return client, state, app


def test_status_is_tenant_aware_store_free_and_omits_principal(environment) -> None:
    client, state, _app = environment

    response = client.get(f"{BASE}/status")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.json() == {
        "schema": "lightwork.privacy-drop-management-status.v1",
        "enabled": True,
        "configured": True,
        "configured_for_attempt": True,
        "locally_operational": True,
            "request_executable": False,
            "request_execution_blocker": "readiness_unverified",
            "ready": True,
        "configuration": {
            "custom_enabled_probe_configured": True,
            "store_factory_configured": True,
            "authority_resolver_configured": True,
            "operational_readiness_probe_configured": True,
            "operational_readiness_checked": True,
            "operational_readiness_verified": True,
            "store_opened_for_status": False,
            "record_authority_resolved_for_status": False,
        },
        "authority_counts": {
            "active_brokers": 0,
            "active_records": 0,
            "approved_outcomes": 0,
        },
        "scheduler": {"installed": False, "running": False, "healthy": False},
        "request_types": ["DataDeletion", "OptOut"],
        "terminal_statuses": ["DELETED", "EXEMPTED", "NOT_FOUND", "OPTED_OUT"],
        "raw_identity_fields_accepted": False,
        "caller_selected_tenant": False,
        "caller_selected_actor": False,
        "caller_selected_subject_binding": False,
        "caller_selected_broker_registration": False,
        "independent_outcome_evidence_required": True,
        "network_io": False,
        "live_drop_interoperability_verified": False,
        "legal_acceptance_verified": False,
    }
    assert state.enabled_calls == [TENANT]
    assert state.readiness_calls == [TENANT]
    assert state.factory_calls == []
    assert state.resolver_calls == []
    assert state.subject not in response.text
    assert "principal" not in response.text


def test_status_does_not_infer_readiness_from_callable_dependencies(environment) -> None:
    client, state, app = environment
    app.state.privacy_drop_management_readiness_probe = None

    response = client.get(f"{BASE}/status")

    assert response.status_code == 200
    assert response.json()["configured"] is True
    assert response.json()["ready"] is False
    assert response.json()["configuration"]["operational_readiness_checked"] is False
    assert state.readiness_calls == []
    assert state.factory_calls == []
    assert state.resolver_calls == []


def test_status_requires_a_boolean_readiness_result_and_sanitizes_failures(
    environment,
) -> None:
    client, state, app = environment
    state.readiness = False

    not_ready = client.get(f"{BASE}/status")

    assert not_ready.status_code == 200
    assert not_ready.json()["ready"] is False
    assert not_ready.json()["configuration"]["operational_readiness_checked"] is True
    assert not_ready.json()["configuration"]["operational_readiness_verified"] is False

    app.state.privacy_drop_management_readiness_probe = lambda _tenant: 1
    malformed = client.get(f"{BASE}/status")
    assert malformed.status_code == 503
    assert malformed.json()["detail"] == "DROP management readiness is unavailable"

    def fail_readiness(_tenant: str) -> bool:
        raise RuntimeError("private readiness detail")

    app.state.privacy_drop_management_readiness_probe = fail_readiness
    failed = client.get(f"{BASE}/status")
    assert failed.status_code == 503
    assert failed.json()["detail"] == "DROP management readiness is unavailable"
    assert "private readiness detail" not in failed.text


@pytest.mark.parametrize("probe_mode", ["false", "missing", "malformed", "failure"])
def test_operations_require_verified_readiness_before_opening_composition(
    environment,
    probe_mode: str,
) -> None:
    client, state, app = environment
    if probe_mode == "false":
        state.readiness = False
    elif probe_mode == "missing":
        app.state.privacy_drop_management_readiness_probe = None
    elif probe_mode == "malformed":
        app.state.privacy_drop_management_readiness_probe = lambda _tenant: 1
    else:
        def fail_readiness(_tenant: str) -> bool:
            raise RuntimeError("private readiness operation detail")

        app.state.privacy_drop_management_readiness_probe = fail_readiness

    response = client.post(f"{BASE}/{DROP_ID}/request", json=_create_body())

    assert response.status_code == 503
    expected = (
        "DROP management operational readiness is not verified"
        if probe_mode in {"false", "missing"}
        else "DROP management readiness is unavailable"
    )
    assert response.json()["detail"] == expected
    assert "private readiness operation detail" not in response.text
    assert state.factory_calls == []
    assert state.resolver_calls == []


def test_disabled_or_non_boolean_capability_fails_closed_without_store(environment) -> None:
    client, state, app = environment
    state.enabled = False

    status = client.get(f"{BASE}/status")
    denied = client.post(f"{BASE}/{DROP_ID}/request", json=_create_body())

    assert status.status_code == 200
    assert status.json()["enabled"] is False
    assert status.json()["ready"] is False
    assert denied.status_code == 403
    assert state.factory_calls == []

    app.state.privacy_drop_management_enabled_probe = lambda _tenant: 1
    invalid = client.get(f"{BASE}/status")
    assert invalid.status_code == 503
    assert invalid.json()["detail"] == "DROP management configuration is unavailable"
    assert state.factory_calls == []


def test_missing_or_malformed_server_composition_is_503(environment) -> None:
    client, state, app = environment
    app.state.privacy_drop_management_store_factory = None

    status = client.get(f"{BASE}/status")
    response = client.post(f"{BASE}/{DROP_ID}/request", json=_create_body())

    assert status.status_code == 200
    assert status.json()["ready"] is False
    assert response.status_code == 503
    assert response.json()["detail"] == "DROP management composition is unavailable"
    assert state.resolver_calls == []


def test_create_uses_exact_server_authority_and_returns_a_safe_projection(environment) -> None:
    client, state, _app = environment

    first = client.post(f"{BASE}/{DROP_ID}/request", json=_create_body())
    replay = client.post(f"{BASE}/{DROP_ID}/request", json=_create_body())

    assert first.status_code == 201, first.text
    assert replay.status_code == 201
    assert first.json() == replay.json()
    payload = first.json()
    assert payload["schema"] == "lightwork.privacy-drop-request-api.v1"
    assert payload["drop_id"] == DROP_ID
    assert payload["request_type"] == "DataDeletion"
    assert payload["status"] == "PENDING"
    assert payload["revision"] == 1
    assert "tenant_id" not in payload
    assert TENANT not in first.text
    assert state.subject not in first.text
    assert _digest("server-subject-binding") not in first.text
    assert _digest("server-broker-binding") not in first.text
    assert len(state.factory_calls) == 2
    tenant, actor, request = state.factory_calls[0]
    assert tenant == TENANT
    assert actor.startswith("drop-principal-")
    assert isinstance(request, Request)
    selectors = state.resolver_calls[0]
    assert selectors == {
        "tenant_id": TENANT,
        "drop_id": DROP_ID,
        "request_type": "DataDeletion",
        "template_id": TEMPLATE_ID,
        "language": "en-US",
        "request": request,
    }
    name, args, kwargs = state.store.calls[0]
    assert name == "create_request"
    assert type(args[0]) is drop.DROPRecordAuthority
    assert args[0].record_revision == 7
    assert kwargs == {
        "expected_revision": 0,
        "idempotency_key": "create-drop-12345",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "tenant-attacker"),
        ("actor_ref", "attacker"),
        ("reviewer_ref", "attacker"),
        ("subject_binding_sha256", "a" * 64),
        ("broker_registration_sha256", "b" * 64),
        ("authority_sha256", "c" * 64),
        ("outcome_evidence", {"approved": True}),
        ("record_revision", 99),
    ],
)
def test_create_rejects_all_caller_owned_authority_fields(environment, field, value) -> None:
    client, state, _app = environment

    response = client.post(
        f"{BASE}/{DROP_ID}/request",
        json=_create_body(**{field: value}),
    )

    assert response.status_code == 422
    assert state.factory_calls == []
    assert state.resolver_calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "tenant-attacker"),
        ("actor_ref", "attacker"),
        ("reviewer_ref", "attacker"),
        ("evidence_sha256", "a" * 64),
        ("deletion_verified", True),
        ("provider_operations_complete", True),
    ],
)
def test_update_rejects_caller_actor_reviewer_and_outcome_evidence(
    environment,
    field,
    value,
) -> None:
    client, state, _app = environment
    body = {
        "status": "DELETED",
        "expected_revision": 1,
        "idempotency_key": "finish-drop-12345",
        field: value,
    }

    response = client.put(f"{BASE}/{DROP_ID}", json=body)

    assert response.status_code == 422
    assert state.factory_calls == []
    assert state.resolver_calls == []


def test_update_uses_only_server_actor_and_current_authority(environment) -> None:
    client, state, _app = environment

    response = client.put(
        f"{BASE}/{DROP_ID}",
        json={
            "status": "DELETED",
            "expected_revision": 1,
            "idempotency_key": "finish-drop-12345",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "DELETED"
    assert response.json()["revision"] == 2
    name, args, kwargs = state.store.calls[-1]
    assert name == "update_status"
    assert type(args[0]) is drop.DROPRecordAuthority
    assert kwargs["actor_ref"] == state.factory_calls[-1][1]
    assert kwargs["actor_ref"].startswith("drop-principal-")
    assert set(kwargs) == {
        "status",
        "expected_revision",
        "idempotency_key",
        "actor_ref",
    }
    assert state.permissions[-1] == "admin"


@pytest.mark.parametrize(
    "mutation",
    [
        {"tenant_id": "tenant-other"},
        {"drop_id": DROP_ID + 1},
        {"request_type": "OptOut"},
        {"template_id": "5f6d5f9a-8a2a-46ec-b9bb-af5c2783cc63"},
        {"language": "fr"},
    ],
)
def test_authority_misbinding_is_rejected_before_store_mutation(environment, mutation) -> None:
    client, state, _app = environment

    def mutate(authority):
        return replace(authority, **mutation, authority_sha256="").normalized()

    state.authority_mutator = mutate
    response = client.post(f"{BASE}/{DROP_ID}/request", json=_create_body())

    assert response.status_code == 409
    assert response.json()["detail"] == "DROP record authority changed"
    assert state.store.calls == []


def test_store_and_record_misbinding_fail_closed(environment) -> None:
    client, state, _app = environment
    state.store.tenant_id = "tenant-other"

    wrong_store = client.get(f"{BASE}/{DROP_ID}")

    assert wrong_store.status_code == 503
    assert state.resolver_calls == []

    state.store.tenant_id = TENANT
    state.record_override = _record(_authority(tenant_id="tenant-other"))
    wrong_record = client.get(f"{BASE}/{DROP_ID}")
    assert wrong_record.status_code == 503
    assert wrong_record.json()["detail"] == "DROP management returned an invalid record"


def test_static_integrity_route_is_store_scoped_and_does_not_resolve_a_record(
    environment,
) -> None:
    client, state, _app = environment

    response = client.get(f"{BASE}/integrity")

    assert response.status_code == 200, response.text
    assert response.json() == {
        "schema": "lightwork.privacy-drop-management-integrity.v1",
        "valid": True,
    }
    assert state.store.calls[-1] == ("verify_integrity", (), {})
    assert state.resolver_calls == []
    assert client.get(f"{BASE}/{DROP_ID}/integrity").status_code == 404

    state.integrity = False
    failed = client.get(f"{BASE}/integrity")
    assert failed.status_code == 503
    assert failed.json()["detail"] == "DROP management integrity verification failed"


def test_errors_are_sanitized_and_queries_cannot_select_authority(environment) -> None:
    client, state, _app = environment
    secret = "raw-provider-secret-and-subject-email@example.test"

    query = client.get(f"{BASE}/{DROP_ID}?tenant_id=tenant-other")
    assert query.status_code == 422
    assert state.factory_calls == []

    state.store_failure = drop.DROPManagementConflict(secret)
    conflict = client.get(f"{BASE}/{DROP_ID}")
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == ("DROP request conflicts with current authority or state")
    assert secret not in conflict.text

    state.store_failure = None
    state.resolver_failure = RuntimeError(secret)
    unavailable = client.get(f"{BASE}/{DROP_ID}")
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == "DROP record authority is unavailable"
    assert secret not in unavailable.text


def test_openapi_has_no_tenant_actor_evidence_or_maintenance_inputs(environment) -> None:
    _client, _state, app = environment
    schemas = {
        "create": api.CreateDROPRequestIn.model_json_schema()["properties"],
        "update": api.UpdateDROPStatusIn.model_json_schema()["properties"],
    }
    forbidden = {
        "tenant",
        "tenant_id",
        "actor_ref",
        "reviewer_ref",
        "subject_binding_sha256",
        "broker_registration_sha256",
        "outcome_evidence",
        "maintenance_authority",
    }
    assert all(not forbidden.intersection(fields) for fields in schemas.values())
    paths = app.openapi()["paths"]
    assert f"{BASE}/integrity" in paths
    assert f"{BASE}/{{drop_id}}/integrity" not in paths


def test_main_dashboard_mounts_the_closed_drop_api_surface() -> None:
    from maverick_dashboard.app import app as dashboard_app

    paths = set(dashboard_app.openapi()["paths"])
    assert {
        f"{BASE}/status",
        f"{BASE}/integrity",
        f"{BASE}/{{drop_id}}/request",
        f"{BASE}/{{drop_id}}",
    }.issubset(paths)
    assert f"{BASE}/{{drop_id}}/integrity" not in paths
