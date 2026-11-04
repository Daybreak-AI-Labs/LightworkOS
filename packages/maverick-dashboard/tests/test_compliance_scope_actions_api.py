from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import compliance_scope_actions as actions
from maverick_dashboard import compliance_scope_actions_api as api

API = "/api/v1/compliance/scope-actions"
NOW = 2_100_000_000.0
SIGNING_SECRET = b"scope-action-signing-secret-never-persisted-123456"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _responsibilities() -> dict[str, str]:
    return {
        "first_line": "ref:business-owner",
        "second_line": "ref:risk-owner",
        "control_owner": "ref:control-owner",
        "evidence_owner": "ref:evidence-owner",
    }


def _finalized_scope() -> dict[str, object]:
    assignments = _responsibilities()
    return {
        "tenant_id": "tenant-a",
        "scope_id": "scope-final-a",
        "scope_revision": 3,
        "scope_integrity_sha256": _digest("scope-v3"),
        "assessment_id": "assessment-a",
        "assessment_revision": 11,
        "assessment_integrity_sha256": _digest("assessment-v11"),
        "status": "finalized",
        "applicable_frameworks": ["framework-baseline", "framework-privacy"],
        "control_applicability": [
            {
                "framework_ref": "framework-baseline",
                "control_ref": "control-inventory",
                "reason_codes": ["baseline_scope", "system_present"],
                "responsibilities": assignments,
            },
            {
                "framework_ref": "framework-privacy",
                "control_ref": "control-records",
                "reason_codes": ["regulated_data"],
                "responsibilities": assignments,
            },
        ],
        "responsibility_assignments": assignments,
        "retained_until": NOW + 20_000,
    }


def _catalog_entries() -> list[dict[str, object]]:
    return [
        {
            "entry_id": "map-inventory",
            "framework_ref": "framework-baseline",
            "scope_control_ref": "control-inventory",
            "desired_control_ref": "register-asset-inventory",
            "desired_control_state": "planned",
            "control_owner_role": "control_owner",
            "evidence_tasks": [
                {
                    "evidence_mapping_ref": "evidence-map-shared-inventory",
                    "task_kind": "collect",
                    "owner_role": "evidence_owner",
                    "cadence": "quarterly",
                }
            ],
        },
        {
            "entry_id": "map-records",
            "framework_ref": "framework-privacy",
            "scope_control_ref": "control-records",
            "desired_control_ref": "register-data-records",
            "desired_control_state": "not_started",
            "control_owner_role": "second_line",
            "evidence_tasks": [
                {
                    "evidence_mapping_ref": "evidence-map-record-review",
                    "task_kind": "review",
                    "owner_role": "second_line",
                    "cadence": "annual",
                },
                {
                    "evidence_mapping_ref": "evidence-map-shared-inventory",
                    "task_kind": "collect",
                    "owner_role": "evidence_owner",
                    "cadence": "quarterly",
                },
            ],
        },
    ]


def _catalog_body() -> dict[str, object]:
    return {
        "entries": _catalog_entries(),
        "expected_latest_version": 0,
        "idempotency_key": "catalog-create",
    }


class LocalApplier:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.outcomes = ["no_change", "reconciled", "rolled_back"]

    def __call__(self, request: Mapping[str, object]) -> dict[str, object]:
        captured = copy.deepcopy(dict(request))
        self.requests.append(captured)
        operation = str(request["operation"])
        outcome = self.outcomes.pop(0)
        change = "removed" if operation == "rollback" else "updated"
        if outcome == "no_change":
            change = "reused"
        intents = [
            *request["control_intents"],  # type: ignore[misc]
            *request["evidence_task_intents"],  # type: ignore[misc]
        ]
        return {
            "operation": operation,
            "operation_ref": request["operation_ref"],
            "desired_sha256": request["desired_sha256"],
            "outcome": outcome,
            "intent_bindings": [
                {
                    "intent_id": intent["intent_id"],
                    "resource_ref": f"ref:local-{intent['intent_id']}",
                    "change": change,
                }
                for intent in intents
            ],
        }


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    applier = LocalApplier()
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "subject": "author",
        "scope": _finalized_scope(),
        "factory_calls": [],
        "permission_calls": [],
        "factory_error": None,
    }
    database = tmp_path / "compliance-scope-actions.sqlite3"

    def require_enabled() -> None:
        if not state["enabled"]:
            raise actions.ComplianceScopeActionConfigError("disabled secret detail")

    def tenant_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("tenant", permission))

    def global_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("global", permission))

    monkeypatch.setattr(actions, "require_enabled", require_enabled)
    monkeypatch.setattr(actions, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        if request.headers.get("X-Test-No-Principal") != "1":
            selected = request.headers.get("X-Test-Subject")
            subject = selected if selected is not None else str(state["subject"])
            request.state.principal = SimpleNamespace(principal=f"user:{subject}")
        return await call_next(request)

    def store_factory(**kwargs):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(kwargs)
        error = state["factory_error"]
        if isinstance(error, BaseException):
            raise error

        def scope_resolver(_tenant: str, _scope_id: str):
            return copy.deepcopy(state["scope"])

        return actions.ComplianceScopeActionStore(
            database,
            scope_resolver=scope_resolver,
            config_gate=lambda: None,
            principal_resolver=kwargs["principal_resolver"],
            apply_callback=kwargs["apply_callback"],
            signing_key_resolver=lambda _tenant, _ref: SIGNING_SECRET,
            clock=lambda: NOW,
        )

    app.state.compliance_scope_actions_store_factory = store_factory
    app.state.compliance_scope_actions_apply_callback = applier
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    return client, database, state, applier


def _create_catalog(client: TestClient, *, actor: str = "catalog-author") -> dict:
    response = client.put(
        f"{API}/catalogs/catalog-a/versions",
        headers={"X-Test-Subject": actor},
        json=_catalog_body(),
    )
    assert response.status_code == 200, response.text
    return response.json()


def _publish_catalog(client: TestClient) -> dict:
    created = _create_catalog(client)
    response = client.post(
        f"{API}/catalogs/catalog-a/versions/1/approve",
        headers={"X-Test-Subject": "catalog-reviewer"},
        json={
            "expected_revision": created["revision"],
            "idempotency_key": "catalog-approve",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _create_plan(client: TestClient) -> dict:
    response = client.put(
        f"{API}/scopes/scope-final-a/plans/plan-a",
        headers={"X-Test-Subject": "scope-planner"},
        json={
            "catalog_id": "catalog-a",
            "catalog_version": 1,
            "expected_scope_revision": 3,
            "retained_until": NOW + 10_000,
            "idempotency_key": "plan-create",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _approve_plan(client: TestClient, revision: int = 1) -> dict:
    response = client.post(
        f"{API}/plans/plan-a/approve",
        headers={"X-Test-Subject": "plan-reviewer"},
        json={
            "expected_revision": revision,
            "idempotency_key": "plan-approve",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_status_is_store_free_honest_default_off_and_requires_principal(
    environment, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _database, state, _applier = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    status = response.json()
    assert status["enabled"] is True
    assert status["apply_callback_configured"] is True
    for boundary in (
        "licensed_framework_content_included",
        "raw_evidence_persisted",
        "free_text_task_descriptions_persisted",
        "arbitrary_code_or_expression_evaluation",
        "built_in_provider_writes",
        "live_provider_acceptance_verified",
        "legal_or_certification_determination",
        "apply_callback_invoked_by_status",
        "network_io_performed_by_adapter",
        "external_provider_writes_performed_by_adapter",
        "live_acceptance_verified",
        "status_request_external_network_io",
    ):
        assert status[boundary] is False
    assert state["factory_calls"] == []

    state["enabled"] = False
    assert client.get(f"{API}/status").json()["enabled"] is False
    blocked = client.get(f"{API}/plans/missing")
    assert blocked.status_code == 403
    assert blocked.json() == {"detail": "compliance scope actions are disabled"}
    assert "secret" not in blocked.text
    assert state["factory_calls"] == []

    state["enabled"] = True
    monkeypatch.setattr("maverick_dashboard.auth.anonymous_local_access_allowed", lambda: False)
    monkeypatch.setattr("maverick_dashboard.auth._dashboard_token_authenticated", lambda _r: False)
    unauthenticated = client.get(
        f"{API}/status",
        headers={"X-Test-No-Principal": "1"},
    )
    assert unauthenticated.status_code == 401


def test_status_grants_a_synthetic_operator_ref_under_genuine_auth_off(environment) -> None:
    """A missing principal is not ALWAYS a 401: genuine local auth-off mode
    and a valid static dashboard bearer are both already-authenticated
    shapes require_permission() itself accepts -- so /status (and
    every other route here) must succeed for them too, not just for a named
    principal."""
    client, _database, _state, _applier = environment
    response = client.get(
        f"{API}/status",
        headers={"X-Test-No-Principal": "1"},
    )
    assert response.status_code == 200


def test_exact_tenant_hashed_principal_and_unicode_isolation(environment) -> None:
    client, _database, state, _applier = environment
    expected = (
        "csa-principal-"
        + hashlib.sha256(
            b"lightwork.compliance-scope-actions.identity.v1:tenant-a:user:author"
        ).hexdigest()[:32]
    )
    assert client.get(f"{API}/status").json()["principal_ref"] == expected

    created = _create_catalog(client, actor="author")
    assert created["tenant_id"] == "tenant-a"
    assert created["created_by"] == expected
    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    assert calls[-1]["tenant_id"] == "tenant-a"
    assert calls[-1]["principal_ref"] == expected
    assert calls[-1]["principal_resolver"]() == expected
    assert calls[-1]["apply_callback"] is client.app.state.compliance_scope_actions_apply_callback

    state["subject"] = "操作者-Δ"
    unicode_ref = client.get(f"{API}/status").json()["principal_ref"]
    expected_unicode = (
        "csa-principal-"
        + hashlib.sha256(
            "lightwork.compliance-scope-actions.identity.v1:tenant-a:user:操作者-Δ".encode()
        ).hexdigest()[:32]
    )
    assert unicode_ref == expected_unicode
    assert "操作者" not in unicode_ref
    assert unicode_ref != expected

    state["tenant"] = "tenant-b"
    isolated = client.get(f"{API}/catalogs/catalog-a/versions/1")
    assert isolated.status_code == 404
    assert isolated.json() == {"detail": "compliance scope-action record was not found"}


def test_closed_bodies_reject_authority_raw_content_secrets_targets_and_code(
    environment,
) -> None:
    client, _database, _state, _applier = environment
    for field in (
        "tenant",
        "tenant_id",
        "actor",
        "actor_ref",
        "principal_ref",
        "framework_text",
        "raw_evidence",
        "signing_key_value",
        "provider",
        "provider_id",
        "target",
        "target_id",
        "code",
        "expression",
    ):
        response = client.put(
            f"{API}/catalogs/unsafe-{field}/versions",
            json={**_catalog_body(), field: "sensitive secret framework text"},
        )
        assert response.status_code == 422
        assert response.json() == {"detail": "compliance scope-action request is invalid"}
        assert "sensitive secret" not in response.text

    nested = _catalog_body()
    nested["entries"][0]["raw_evidence"] = "private customer evidence"  # type: ignore[index]
    response = client.put(f"{API}/catalogs/nested-unsafe/versions", json=nested)
    assert response.status_code == 422
    assert "private customer evidence" not in response.text

    wrong_type = {
        **_catalog_body(),
        "expected_latest_version": "0",
    }
    assert client.put(f"{API}/catalogs/string-version/versions", json=wrong_type).status_code == 422
    literal_key = client.put(
        f"{API}/plans/plan-a/exports/export-a",
        json={
            "signing_key_ref": "literal-secret-value",
            "retained_until": NOW + 100,
            "idempotency_key": "bad-key",
        },
    )
    assert literal_key.status_code == 422
    assert "literal-secret-value" not in literal_key.text
    extra_key = client.put(
        f"{API}/plans/plan-a/exports/export-b",
        json={
            "signing_key_ref": "vault:scope-key",
            "signing_key": "literal-secret-value",
            "retained_until": NOW + 100,
            "idempotency_key": "bad-key-field",
        },
    )
    assert extra_key.status_code == 422


def test_catalog_four_eyes_cas_and_idempotency(environment) -> None:
    client, _database, _state, _applier = environment
    created = _create_catalog(client)
    replay = _create_catalog(client)
    assert replay == created

    self_approval = client.post(
        f"{API}/catalogs/catalog-a/versions/1/approve",
        headers={"X-Test-Subject": "catalog-author"},
        json={"expected_revision": 1, "idempotency_key": "self-approve"},
    )
    assert self_approval.status_code == 403
    assert self_approval.json() == {"detail": "compliance scope-action operation is not permitted"}
    approved = client.post(
        f"{API}/catalogs/catalog-a/versions/1/approve",
        headers={"X-Test-Subject": "catalog-reviewer"},
        json={"expected_revision": 1, "idempotency_key": "catalog-approve"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "published"
    assert approved.json()["reviewed_by"] != approved.json()["created_by"]
    assert (
        client.post(
            f"{API}/catalogs/catalog-a/versions/1/approve",
            headers={"X-Test-Subject": "catalog-reviewer"},
            json={"expected_revision": 1, "idempotency_key": "catalog-approve"},
        ).json()
        == approved.json()
    )

    stale = client.put(
        f"{API}/catalogs/catalog-a/versions",
        json={**_catalog_body(), "idempotency_key": "stale-catalog"},
    )
    assert stale.status_code == 409


def test_scope_authority_drift_unmapped_control_and_shared_evidence_dedup(
    environment,
) -> None:
    client, _database, state, _applier = environment
    _publish_catalog(client)
    plan = _create_plan(client)
    assert plan["scope_revision"] == 3
    assert plan["assessment_revision"] == 11
    assert len(plan["control_intents"]) == 2
    assert len(plan["evidence_task_intents"]) == 2
    shared = [
        item
        for item in plan["evidence_task_intents"]
        if item["evidence_mapping_ref"] == "evidence-map-shared-inventory"
    ]
    assert len(shared) == 1
    assert shared[0]["control_refs"] == [
        "register-asset-inventory",
        "register-data-records",
    ]

    replay = _create_plan(client)
    assert replay == plan
    scope = state["scope"]
    assert isinstance(scope, dict)
    scope["scope_revision"] = 4
    scope["scope_integrity_sha256"] = _digest("scope-v4")
    drifted = client.post(
        f"{API}/plans/plan-a/approve",
        headers={"X-Test-Subject": "plan-reviewer"},
        json={"expected_revision": 1, "idempotency_key": "drifted-approve"},
    )
    assert drifted.status_code == 409
    scope["scope_revision"] = 3
    scope["scope_integrity_sha256"] = _digest("scope-v3")

    controls = scope["control_applicability"]
    assert isinstance(controls, list)
    controls.append(
        {
            "framework_ref": "framework-baseline",
            "control_ref": "control-unmapped",
            "reason_codes": ["new_reason"],
            "responsibilities": _responsibilities(),
        }
    )
    unmapped = client.put(
        f"{API}/scopes/scope-final-a/plans/plan-unmapped",
        headers={"X-Test-Subject": "scope-planner"},
        json={
            "catalog_id": "catalog-a",
            "catalog_version": 1,
            "expected_scope_revision": 3,
            "retained_until": NOW + 100,
            "idempotency_key": "unmapped-plan",
        },
    )
    assert unmapped.status_code == 409


def test_apply_requires_server_callback_and_preserves_approved_state(environment) -> None:
    client, _database, _state, _applier = environment
    _publish_catalog(client)
    plan = _create_plan(client)
    approved = _approve_plan(client, plan["revision"])
    client.app.state.compliance_scope_actions_apply_callback = None
    response = client.post(
        f"{API}/plans/plan-a/apply",
        headers={"X-Test-Subject": "executor"},
        json={"expected_revision": approved["revision"], "idempotency_key": "apply-none"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "compliance scope-action configuration is unavailable"}
    current = client.get(f"{API}/plans/plan-a").json()
    assert current["status"] == "approved"
    assert current["revision"] == approved["revision"]


def test_apply_no_change_reconcile_rollback_export_integrity_and_permissions(
    environment,
) -> None:
    client, database, state, applier = environment
    _publish_catalog(client)
    plan = _create_plan(client)
    approved = _approve_plan(client, plan["revision"])

    applied = client.post(
        f"{API}/plans/plan-a/apply",
        headers={"X-Test-Subject": "executor"},
        json={"expected_revision": approved["revision"], "idempotency_key": "apply"},
    )
    assert applied.status_code == 200, applied.text
    assert applied.json()["status"] == "no_change"
    assert applied.json()["last_receipt"]["outcome"] == "no_change"
    assert {item["change"] for item in applied.json()["last_receipt"]["intent_bindings"]} == {
        "reused"
    }
    replay = client.post(
        f"{API}/plans/plan-a/apply",
        headers={"X-Test-Subject": "executor"},
        json={"expected_revision": approved["revision"], "idempotency_key": "apply"},
    )
    assert replay.json() == applied.json()
    assert len(applier.requests) == 1

    reconciled = client.post(
        f"{API}/plans/plan-a/reconcile",
        headers={"X-Test-Subject": "executor"},
        json={
            "expected_revision": applied.json()["revision"],
            "idempotency_key": "reconcile",
        },
    )
    assert reconciled.status_code == 200, reconciled.text
    assert reconciled.json()["last_outcome"] == "reconciled"
    rolled_back = client.post(
        f"{API}/plans/plan-a/rollback",
        headers={"X-Test-Subject": "executor"},
        json={
            "expected_revision": reconciled.json()["revision"],
            "idempotency_key": "rollback",
        },
    )
    assert rolled_back.status_code == 200, rolled_back.text
    assert rolled_back.json()["status"] == "rolled_back"

    history = client.get(f"{API}/plans/plan-a/history")
    assert history.status_code == 200
    assert history.json()["count"] == 5
    assert [item["status"] for item in history.json()["items"]] == [
        "draft",
        "approved",
        "no_change",
        "applied",
        "rolled_back",
    ]
    exported = client.put(
        f"{API}/plans/plan-a/exports/export-a",
        headers={"X-Test-Subject": "exporter"},
        json={
            "signing_key_ref": "vault:scope-action-key-v1",
            "retained_until": NOW + 5_000,
            "idempotency_key": "export",
        },
    )
    assert exported.status_code == 200, exported.text
    assert exported.json()["signature_hmac_sha256"]
    assert SIGNING_SECRET.decode() not in exported.text
    fetched = client.get(f"{API}/exports/export-a")
    assert fetched.status_code == 200
    assert fetched.json() == exported.json()
    integrity = client.get(
        f"{API}/integrity",
        headers={"X-Test-Subject": "auditor"},
    )
    assert integrity.status_code == 200, integrity.text
    assert integrity.json()["valid"] is True

    persisted = database.read_bytes()
    wal = Path(f"{database}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    assert SIGNING_SECRET not in persisted
    assert b"licensed framework prose" not in persisted
    assert b"private customer evidence" not in persisted
    assert "raw_evidence" not in json.dumps(applier.requests)
    calls = state["permission_calls"]
    assert isinstance(calls, list)
    assert ("tenant", "view") in calls
    assert ("tenant", "operate") in calls
    assert ("global", "admin") in calls
    assert ("global", "audit") in calls


def test_integrity_unexpected_and_factory_errors_are_generic(environment) -> None:
    client, _database, state, _applier = environment

    class IntegrityStore:
        @staticmethod
        def get_plan(_tenant: str, _plan: str):
            raise actions.ComplianceScopeActionIntegrityError("sensitive row digest")

    client.app.state.compliance_scope_actions_store_factory = lambda **_kwargs: IntegrityStore()
    integrity = client.get(f"{API}/plans/plan-a")
    assert integrity.status_code == 503
    assert integrity.json() == {"detail": "compliance scope-action integrity verification failed"}
    assert "sensitive row" not in integrity.text

    class UnexpectedStore:
        @staticmethod
        def get_plan(_tenant: str, _plan: str):
            raise RuntimeError("database password and path")

    client.app.state.compliance_scope_actions_store_factory = lambda **_kwargs: UnexpectedStore()
    unexpected = client.get(f"{API}/plans/plan-a")
    assert unexpected.status_code == 503
    assert unexpected.json() == {"detail": "compliance scope-action operation failed"}
    assert "password" not in unexpected.text

    def original_factory(**_kwargs):
        raise RuntimeError("constructor secret")

    client.app.state.compliance_scope_actions_store_factory = original_factory
    factory = client.get(f"{API}/plans/plan-a")
    assert factory.status_code == 503
    assert factory.json() == {"detail": "compliance scope-action store is unavailable"}
    assert "constructor secret" not in factory.text
    assert state["enabled"] is True


def test_default_factory_joins_tenant_local_scoping_and_action_stores(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick import compliance_scoping, paths

    captured: dict[str, object] = {"data_calls": []}

    class FakeScopingStore:
        def __init__(self, path, *, principal_resolver):
            captured["scoping_path"] = path
            captured["scoping_principal"] = principal_resolver()

    class FakeActionStore:
        def __init__(self, path, **kwargs):
            captured["action_path"] = path
            captured["action_kwargs"] = kwargs

    def fake_data_dir(*parts: str, tenant: str):
        calls = captured["data_calls"]
        assert isinstance(calls, list)
        calls.append((parts, tenant))
        return tmp_path.joinpath(*parts)

    resolver = object()
    monkeypatch.setattr(compliance_scoping, "ComplianceScopingStore", FakeScopingStore)
    monkeypatch.setattr(actions, "ComplianceScopeActionStore", FakeActionStore)
    monkeypatch.setattr(actions, "resolver_from_scoping_store", lambda _store: resolver)
    monkeypatch.setattr(paths, "data_dir", fake_data_dir)
    callback = LocalApplier()
    result = api._default_store_for(
        "tenant-a",
        "csa-principal-abc",
        apply_callback=callback,
    )
    assert isinstance(result, FakeActionStore)
    assert captured["scoping_principal"] == "csa-principal-abc"
    assert captured["data_calls"] == [
        (("tech_risk_compliance", "compliance-scoping.sqlite3"), "tenant-a"),
        (("tech_risk_compliance", "compliance-scope-actions.sqlite3"), "tenant-a"),
    ]
    kwargs = captured["action_kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["scope_resolver"] is resolver
    assert kwargs["principal_resolver"]() == "csa-principal-abc"
    assert kwargs["apply_callback"] is callback


def test_all_core_operations_are_mounted_and_adapter_has_no_network_client(environment) -> None:
    client, _database, _state, _applier = environment
    paths = set(client.app.openapi()["paths"])
    expected = {
        f"{API}/status",
        f"{API}/catalogs/{{catalog_id}}/versions",
        f"{API}/catalogs/{{catalog_id}}/versions/{{version}}",
        f"{API}/catalogs/{{catalog_id}}/versions/{{version}}/approve",
        f"{API}/scopes/{{scope_id}}/plans/{{plan_id}}",
        f"{API}/plans/{{plan_id}}",
        f"{API}/plans/{{plan_id}}/history",
        f"{API}/plans/{{plan_id}}/approve",
        f"{API}/plans/{{plan_id}}/apply",
        f"{API}/plans/{{plan_id}}/reconcile",
        f"{API}/plans/{{plan_id}}/rollback",
        f"{API}/plans/{{plan_id}}/exports/{{export_id}}",
        f"{API}/exports/{{export_id}}",
        f"{API}/integrity",
    }
    assert expected <= paths
    source = Path(api.__file__).read_text(encoding="utf-8")
    for method in (
        "create_catalog_version",
        "get_catalog_version",
        "approve_catalog_version",
        "create_plan",
        "get_plan",
        "get_plan_history",
        "approve_plan",
        "apply_plan",
        "reconcile_plan",
        "rollback_plan",
        "export_plan",
        "get_export",
        "verify_integrity",
    ):
        assert f"store.{method}" in source or f'"{method}"' in source
    for primitive in ("requests.", "httpx.", "urllib.request", "socket."):
        assert primitive not in source


def test_records_list_catalogs_plans_and_reports_per_workspace(environment) -> None:
    client, _database, state, _applier = environment
    empty = client.get(f"{API}/records")
    assert empty.status_code == 200, empty.text
    assert empty.json()["plans"] == [] and empty.json()["can_create_tasks"] is True
    _publish_catalog(client)
    _create_plan(client)
    approved = _approve_plan(client)
    listed = client.get(f"{API}/records").json()
    assert [c["status"] for c in listed["catalogs"]] == ["published"]
    plan = listed["plans"][0]
    assert plan["plan_id"] == "plan-a" and plan["approved"] is True
    assert plan["revision"] == approved["revision"] and plan["controls"] >= 1
    assert ("tenant", "view") in state["permission_calls"]
    report = client.post(
        f"{API}/plans/plan-a/report",
        headers={"X-Test-Subject": "scope-planner"},
        json={"idempotency_key": "report-1"},
    )
    assert report.status_code == 200, report.text
    assert report.json()["signing_key_ref"] == api.DEFAULT_REPORT_SIGNING_KEY_REF
    assert client.get(f"{API}/records").json()["reports"][0]["plan_id"] == "plan-a"
    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/records").json()["plans"] == []
