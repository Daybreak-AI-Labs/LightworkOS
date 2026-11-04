from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import third_party_lifecycle as lifecycle
from maverick_dashboard import third_party_lifecycle_api as api
from maverick_dashboard import vendor_profile

API = "/api/v1/third-party/lifecycle"
DAY = 86_400


def _vendor(label: str) -> str:
    return "VMR-" + hashlib.sha256(label.encode()).hexdigest()[:24]


VENDOR_1, VENDOR_CALLBACK, VENDOR_ROLE, VENDOR_LIST = (
    _vendor(label) for label in ("vendor-1", "vendor-callback", "vendor-role", "vendor-list")
)
REGISTERED_VENDORS = frozenset({VENDOR_1, VENDOR_CALLBACK, VENDOR_ROLE, VENDOR_LIST})


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "factory_calls": [],
        "permission_calls": [],
    }
    database = tmp_path / "third-party-lifecycle.sqlite3"

    def require_enabled() -> None:
        if not state["enabled"]:
            raise lifecycle.ThirdPartyLifecycleConfigError("disabled for test")

    monkeypatch.setattr(lifecycle, "require_enabled", require_enabled)
    monkeypatch.setattr(lifecycle, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    # Assessments and lifecycles name a vendor from the Privacy register, and
    # their writes recheck the live workspace at the effect boundary.
    from maverick import paths

    for module in (paths, vendor_profile):
        monkeypatch.setattr(module, "current_tenant_id_strict", lambda: str(state["tenant"]))
    monkeypatch.setattr(
        vendor_profile.vm,
        "get_vendor",
        lambda identifier: {"id": identifier} if identifier in REGISTERED_VENDORS else None,
    )
    state["database"] = database

    def tenant_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("tenant", permission))

    def global_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("global", permission))

    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)
    # The vendor effect guard re-checks the same floors through auth itself.
    monkeypatch.setattr(vendor_profile.auth, "require_permission", tenant_permission)
    monkeypatch.setattr(vendor_profile.auth, "require_global_permission", global_permission)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        subject = request.headers.get("X-Test-Subject", "owner")
        request.state.principal = SimpleNamespace(principal=f"user:{subject}")
        return await call_next(request)

    def store_factory(**kwargs):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(kwargs)
        return lifecycle.ThirdPartyLifecycleStore(
            database,
            config_gate=lambda: None,
            principal_resolver=kwargs["principal_resolver"],
        )

    app.state.third_party_lifecycle_store_factory = store_factory
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "owner"},
    )
    return client, state


def _template_body() -> dict:
    return {
        "title_ref": "title.standard",
        "questions": [
            {
                "question_id": "security-control",
                "domain": "security",
                "prompt_ref": "prompt.security-control",
                "response_type": "boolean",
                "required": True,
                "options": [],
                "condition": None,
                "risk_rules": [],
            }
        ],
        "mitigation_rules": [],
        "expected_latest_version": 0,
        "idempotency_key": "template-create",
    }


def _evaluated_assessment(state: dict, vendor_ref: str) -> None:
    """Give ``vendor_ref`` the complete, evaluated assessment activation needs."""
    acting = {"principal": "author"}
    store = lifecycle.ThirdPartyLifecycleStore(
        state["database"], config_gate=lambda: None,
        principal_resolver=lambda: acting["principal"],
    )
    tenant = str(state["tenant"])
    body = _template_body()
    body.pop("idempotency_key")
    store.create_template_version(tenant, "activation", idempotency_key="activation-template", **body)
    acting["principal"] = "reviewer"
    store.approve_template_version(tenant, "activation", 1, expected_revision=1,
                                   idempotency_key="activation-approve")
    acting["principal"] = "creator"
    store.create_assessment(
        tenant, "activation-assessment", vendor_ref=vendor_ref, template_id="activation",
        template_version=1, owner_ref="owner",
        respondent_assignments={"security-control": "respondent"},
        retention_seconds=DAY, idempotency_key="activation-assessment",
    )
    acting["principal"] = "respondent"
    answered = store.record_response(
        tenant, "activation-assessment", "security-control", value=True,
        evidence_sha256="b" * 64, evidence_refs=["evidence.security"],
        expected_revision=1, idempotency_key="activation-response",
    )
    acting["principal"] = "owner"
    result = store.evaluate_assessment(tenant, "activation-assessment",
                                       expected_revision=answered.revision,
                                       idempotency_key="activation-evaluate")
    assert result.route == "owner_review"


def test_status_is_honest_store_free_and_feature_off_is_403(environment) -> None:
    client, state = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    status = response.json()
    assert status["network_operations_implemented"] is False
    assert status["provider_writes_implemented"] is False
    assert status["live_provider_acceptance_verified"] is False
    assert status["live_customer_acceptance_verified"] is False
    assert status["callback_transport_worker_implemented"] is False
    assert status["callbacks_are_governed_intent_only"] is True
    assert state["factory_calls"] == []

    state["enabled"] = False
    assert client.get(f"{API}/status").json()["enabled"] is False
    denied = client.get(f"{API}/lifecycles/lifecycle-1")
    assert denied.status_code == 403


def test_exact_tenant_and_stable_principal_resolver_binding(environment) -> None:
    client, state = environment
    status = client.get(f"{API}/status").json()
    expected = (
        "tpl-principal-"
        + hashlib.sha256(
            b"lightwork.third-party-lifecycle.identity.v1:tenant-a:user:owner"
        ).hexdigest()[:32]
    )
    assert status["principal_ref"] == expected

    # A free-text vendor slug is not a registered vendor: nothing is created.
    unregistered = client.put(
        f"{API}/lifecycles/lifecycle-1",
        json={"vendor_ref": "vendor-1", "owner_ref": expected, "dependencies": [],
              "retention_seconds": DAY, "idempotency_key": "lifecycle-unregistered"},
    )
    assert unregistered.status_code == 409
    created = client.put(
        f"{API}/lifecycles/lifecycle-1",
        json={
            "vendor_ref": VENDOR_1,
            "owner_ref": expected,
            "dependencies": [],
            "retention_seconds": DAY,
            "idempotency_key": "lifecycle-create",
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["tenant_id"] == "tenant-a"
    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    assert calls[-1]["tenant_id"] == "tenant-a"
    assert calls[-1]["principal_ref"] == expected
    assert calls[-1]["principal_resolver"]() == expected

    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/lifecycles/lifecycle-1").status_code == 404


@pytest.mark.parametrize("field", ["tenant", "tenant_id", "actor", "actor_ref"])
def test_strict_bodies_reject_tenant_and_actor_spoofing(environment, field) -> None:
    client, _state = environment
    response = client.put(
        f"{API}/templates/standard",
        json={**_template_body(), field: "forged"},
    )
    assert response.status_code == 422


def test_strict_types_and_four_eyes_error_translation(environment) -> None:
    client, _state = environment
    numeric_string = {**_template_body(), "expected_latest_version": "0"}
    assert client.put(f"{API}/templates/standard", json=numeric_string).status_code == 422

    created = client.put(f"{API}/templates/standard", json=_template_body())
    assert created.status_code == 200, created.text
    assert created.json()["authored_by"] == client.get(f"{API}/status").json()["principal_ref"]
    approval = {
        "expected_revision": 1,
        "idempotency_key": "template-approve",
    }
    same_actor = client.post(f"{API}/templates/standard/versions/1/approve", json=approval)
    assert same_actor.status_code == 403
    assert "cannot approve their own version" in same_actor.json()["detail"]

    approved = client.post(
        f"{API}/templates/standard/versions/1/approve",
        headers={"X-Test-Subject": "reviewer"},
        json=approval,
    )
    assert approved.status_code == 200, approved.text
    assert (
        approved.json()["approved_by"]
        == client.get(f"{API}/status", headers={"X-Test-Subject": "reviewer"}).json()[
            "principal_ref"
        ]
    )
    stale = client.post(
        f"{API}/templates/standard/versions/1/approve",
        headers={"X-Test-Subject": "reviewer-2"},
        json={**approval, "idempotency_key": "stale", "expected_revision": 1},
    )
    assert stale.status_code == 409

    unsupported = client.post(
        f"{API}/lifecycles/lifecycle-1/transition",
        json={
            "target_stage": "offboarded",
            "reason_code": "skip_controls",
            "expected_revision": 1,
            "idempotency_key": "unsupported-transition",
        },
    )
    assert unsupported.status_code == 422


def test_callback_claim_fail_uses_core_integer_contract_and_redacts_get(
    environment,
) -> None:
    client, _state = environment
    principal = client.get(f"{API}/status").json()["principal_ref"]
    lifecycle_response = client.put(
        f"{API}/lifecycles/lifecycle-callback",
        json={
            "vendor_ref": VENDOR_CALLBACK,
            "owner_ref": principal,
            "dependencies": [
                {
                    "dependency_id": "access-crm",
                    "kind": "access",
                    "reference": "ref-crm",
                    "evidence_sha256": "a" * 64,
                }
            ],
            "retention_seconds": DAY,
            "idempotency_key": "callback-lifecycle-create",
        },
    )
    assert lifecycle_response.status_code == 200, lifecycle_response.text
    plan = client.post(
        f"{API}/lifecycles/lifecycle-callback/offboarding/plan-callback",
        json={
            "tasks": [
                {
                    "task_id": "revoke-crm",
                    "dependency_id": "access-crm",
                    "action": "revoke_access",
                    "assignee_ref": principal,
                    "callback_required": True,
                }
            ],
            "legal_hold": False,
            "legal_hold_evidence_ref": None,
            "maximum_callback_attempts": 2,
            "expected_lifecycle_revision": 1,
            "idempotency_key": "callback-plan-create",
        },
    )
    assert plan.status_code == 200, plan.text

    assert (
        client.post(f"{API}/callbacks/claim", json={"limit": 1, "lease_seconds": 30.0}).status_code
        == 422
    )
    claimed_response = client.post(
        f"{API}/callbacks/claim",
        headers={"X-Test-Subject": "callback-worker"},
        json={"limit": 1, "lease_seconds": 30},
    )
    assert claimed_response.status_code == 200, claimed_response.text
    claimed = claimed_response.json()["items"][0]
    assert claimed["lease_token"]

    detail = client.get(f"{API}/callbacks/{claimed['callback_id']}")
    assert detail.status_code == 200
    assert "lease_token" not in detail.json()

    failed = client.post(
        f"{API}/callbacks/{claimed['callback_id']}/fail",
        headers={"X-Test-Subject": "callback-worker"},
        json={
            "lease_token": claimed["lease_token"],
            "error_code": "temporary-outage",
            "retry_after_seconds": 10,
            "expected_revision": claimed["revision"],
            "idempotency_key": "callback-fail",
        },
    )
    assert failed.status_code == 200, failed.text
    assert failed.json()["state"] == "pending"

    too_many_attempts = client.post(
        f"{API}/lifecycles/lifecycle-callback/offboarding/another-plan",
        json={
            "tasks": [],
            "legal_hold": False,
            "legal_hold_evidence_ref": None,
            "maximum_callback_attempts": 21,
            "expected_lifecycle_revision": 2,
            "idempotency_key": "too-many-attempts",
        },
    )
    assert too_many_attempts.status_code == 422


def test_read_paths_are_local_and_major_routes_are_exposed(environment) -> None:
    client, _state = environment
    paths = set(client.app.openapi()["paths"])
    expected = {
        f"{API}/templates/{{template_id}}",
        f"{API}/assessments/{{assessment_id}}/required-questions",
        f"{API}/assessments/{{assessment_id}}/responses/{{question_id}}",
        f"{API}/assessments/{{assessment_id}}/evaluate",
        f"{API}/assessments/{{assessment_id}}/tasks/{{task_id}}",
        f"{API}/lifecycles/{{lifecycle_id}}/transition",
        f"{API}/lifecycles/{{lifecycle_id}}/offboarding/{{plan_id}}",
        f"{API}/offboarding/{{plan_id}}/legal-hold",
        f"{API}/offboarding/{{plan_id}}/tasks/{{task_id}}",
        f"{API}/offboarding/{{plan_id}}/complete",
        f"{API}/callbacks/claim",
        f"{API}/callbacks/{{callback_id}}/fail",
        f"{API}/callbacks/{{callback_id}}/acknowledge",
        f"{API}/callbacks/{{callback_id}}/requeue",
        f"{API}/exports/{{export_id}}",
        f"{API}/retention/purge",
        f"{API}/integrity",
    }
    assert expected <= paths
    source = Path(api.__file__).read_text(encoding="utf-8")
    for network_primitive in (
        "requests.",
        "httpx.",
        "urllib.request",
        "socket.",
        "execute_callback",
    ):
        assert network_primitive not in source


def test_view_operate_and_admin_permission_floors(environment) -> None:
    client, state = environment
    principal = client.get(f"{API}/status").json()["principal_ref"]
    created = client.put(
        f"{API}/lifecycles/lifecycle-role",
        json={
            "vendor_ref": VENDOR_ROLE,
            "owner_ref": principal,
            "dependencies": [],
            "retention_seconds": DAY,
            "idempotency_key": "role-create",
        },
    )
    assert created.status_code == 200
    _evaluated_assessment(state, VENDOR_ROLE)
    active = client.post(
        f"{API}/lifecycles/lifecycle-role/transition",
        json={
            "target_stage": "active",
            "reason_code": "onboarding-approved",
            "expected_revision": 1,
            "idempotency_key": "role-active",
        },
    )
    assert active.status_code == 200, active.text
    suspended = client.post(
        f"{API}/lifecycles/lifecycle-role/transition",
        json={
            "target_stage": "suspended",
            "reason_code": "risk-review",
            "expected_revision": 2,
            "idempotency_key": "role-suspend",
        },
    )
    assert suspended.status_code == 200, suspended.text
    calls = state["permission_calls"]
    assert isinstance(calls, list)
    assert ("tenant", "view") in calls
    assert calls.count(("tenant", "operate")) >= 2
    assert ("global", "admin") in calls


def test_lists_load_every_record_kind_for_the_workspace(environment) -> None:
    client, state = environment
    principal = client.get(f"{API}/status").json()["principal_ref"]
    assert client.put(f"{API}/templates/standard", json=_template_body()).status_code == 200
    assert client.put(
        f"{API}/lifecycles/lifecycle-list",
        json={"vendor_ref": VENDOR_LIST, "owner_ref": principal, "dependencies": [],
              "retention_seconds": DAY, "idempotency_key": "list-create"},
    ).status_code == 200
    templates = client.get(f"{API}/templates").json()["items"]
    assert [(t["template_id"], t["version"], t["state"]) for t in templates] == [
        ("standard", 1, "pending_approval")
    ]
    lifecycles = client.get(f"{API}/lifecycles").json()["items"]
    assert [item["lifecycle_id"] for item in lifecycles] == ["lifecycle-list"]
    assert client.get(f"{API}/assessments").json() == {"items": []}
    assert client.get(f"{API}/offboarding").json() == {"items": []}
    calls = state["permission_calls"]
    assert calls.count(("tenant", "view")) >= 4
    # Another workspace sees none of it.
    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/templates").json() == {"items": []}
    assert client.get(f"{API}/lifecycles").json() == {"items": []}


def test_lists_are_off_with_the_feature(environment) -> None:
    client, state = environment
    state["enabled"] = False
    for path in ("templates", "assessments", "lifecycles", "offboarding"):
        assert client.get(f"{API}/{path}").status_code == 403


def test_people_list_carries_lifecycle_references(environment, monkeypatch) -> None:
    client, state = environment
    from maverick_dashboard import ui_choices_api

    monkeypatch.setattr(ui_choices_api, "people_choices",
                        lambda: [{"value": "user:ann@example.com", "label": "ann@example.com"}])
    body = client.get(f"{API}/people").json()
    me = client.get(f"{API}/status").json()["principal_ref"]
    assert body["me"] == me
    ann = api._principal_ref_for("tenant-a", "user:ann@example.com")
    assert {"value": ann, "label": "ann@example.com"} in body["items"]
    assert {"value": me, "label": "Me"} in body["items"]
    assert body["named_signin"] is True
    assert ("tenant", "operate") in state["permission_calls"]


def test_shared_local_operator_cannot_author_or_approve_questionnaires(environment, monkeypatch) -> None:
    client, _state = environment
    monkeypatch.setattr(api, "caller_principal", lambda _request: None)
    monkeypatch.setattr(api, "authenticated_subject", lambda _request, **_kwargs: "authorized-local-operator")
    people = client.get(f"{API}/people")
    assert people.status_code == 200
    assert people.json()["named_signin"] is False
    created = client.put(f"{API}/templates/local", json=_template_body())
    assert created.status_code == 403
    assert "individual sign-ins" in created.json()["detail"]
    approval = client.post(
        f"{API}/templates/local/versions/1/approve",
        json={"expected_revision": 1, "idempotency_key": "approval"},
    )
    assert approval.status_code == 403
    assert "individual account" in approval.json()["detail"]


def test_legacy_shared_author_cannot_be_approved_after_owner_claim(environment) -> None:
    client, _state = environment
    synthetic = api._principal_ref_for("tenant-a", "authorized-local-operator")
    store = client.app.state.third_party_lifecycle_store_factory(
        tenant_id="tenant-a", principal_ref=synthetic,
        principal_resolver=lambda: synthetic, request=None,
    )
    store.create_template_version("tenant-a", "legacy", **_template_body())
    listing = client.get(f"{API}/templates")
    assert listing.status_code == 200
    assert listing.json()["items"][0]["needs_named_author"] is True
    approval = client.post(
        f"{API}/templates/legacy/versions/1/approve",
        json={"expected_revision": 1, "idempotency_key": "approval"},
    )
    assert approval.status_code == 409
    assert "new version" in approval.json()["detail"]
