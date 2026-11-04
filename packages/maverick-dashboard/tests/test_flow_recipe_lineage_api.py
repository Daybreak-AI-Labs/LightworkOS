"""HTTP signed lineage with real native capture, crypto and governed stores.

The shared harness stubs OIDC token signature verification. Workspace checks,
native tool authorization/approval, durable capture/review, signing and outboxes
remain actual product implementations. No provider or external connector calls.
"""
from __future__ import annotations

import copy
import json
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick import audit
from maverick.flow import store
from maverick.paths import tenant_scope

from test_support.action_episode_api import (
    CREATE,
    LOOKUP,
    OWNER,
    PRIVATE_REF,
    RATIONALE,
    TENANT,
    _awaiting_review,
    _base,
    _review,
)
from test_support.action_episode_api import harness as harness

BASE = "/api/v1/flows/recipe-lineage"


@pytest.fixture
def enabled(harness):
    harness.flags.update(action_recipe_lineage=True, require_action_recipe_lineage=False,
                         action_evidence_issuer="native-api-test", action_evidence_revoked_keys=[])
    return harness


def accepted(harness, index=0):
    source, run, record = _awaiting_review(harness, index=index, flow_id=f"lineage-source-{index}")
    response = harness.client.post(_base(run) + "/review", json=_review(record))
    assert response.status_code == 200, response.text
    return source, run, response.json()


def grant_body(record):
    return {"expected_revision": record["revision"], "expected_episode_sha256": record["episode_sha256"],
            "use_until": record["retain_until"] - 1, "retain_derived_copies": True,
            "rationale": "Private consent to bounded derived recipe copies."}


def export_body(record):
    return {"expected_revision": record["revision"], "expected_episode_sha256": record["episode_sha256"],
            "expected_grant_sha256": record["grant_sha256"]}


def signed(harness, index=0):
    source, run, record = accepted(harness, index)
    grant = harness.client.post(_base(run) + "/training-grant", json=grant_body(record))
    assert grant.status_code == 200, grant.text
    exported = harness.client.post(_base(run) + "/signed-export", json=export_body(grant.json()))
    assert exported.status_code == 200, exported.text
    assert exported.headers["cache-control"] == "no-store"
    return source, run, exported.json()


def package(harness):
    from maverick.flow.action_provenance import local_trust
    from maverick.flow.recipe_lineage import learn_from_verified_bundles

    sources = [signed(harness, index) for index in range(2)]
    with tenant_scope(tenant=TENANT):
        value = learn_from_verified_bundles([source[2] for source in sources], trust=local_trust(TENANT),
            expected_tenant=TENANT, now=time.time(), allowed_tools=[LOOKUP, CREATE])
    return sources, value


def test_native_http_capture_signed_exports_admission_and_draft_keep_exact_lineage(enabled):
    from maverick.flow.action_provenance import local_trust, verify_bundle

    sources, value = package(enabled)
    with tenant_scope(tenant=TENANT):
        checked = verify_bundle(sources[0][2], trust=local_trust(TENANT), expected_tenant=TENANT, now=time.time())
    assert checked["signature_status"] == "trusted" and checked["live_status"] == "not_checked"
    admitted = enabled.client.post(BASE, json={"package": value})
    assert admitted.status_code == 200, admitted.text
    metadata = admitted.json()
    assert metadata["status"] == "admitted" and metadata["current_eligibility"] == "accepted"
    assert PRIVATE_REF not in admitted.text and RATIONALE not in admitted.text
    current = enabled.client.get(BASE + "/" + metadata["id"])
    assert current.status_code == 200 and "package" not in current.json()
    detail = enabled.client.get(BASE + "/" + metadata["id"] + "/detail")
    assert detail.status_code == 200 and detail.json()["package"] == value
    draft = enabled.client.post(BASE + "/" + metadata["id"] + "/draft", json={"flow_id": "derived", "name": "Derived"})
    assert draft.status_code == 200, draft.text
    assert draft.json()["learned_recipe"] == value["artifact"]
    assert draft.json()["recipe_lineage"] == metadata["reference"]
    assert draft.json()["owner"] == OWNER and len(enabled.calls) == 4
    with tenant_scope(tenant=TENANT):
        assert store.load_flow("derived") is None


@pytest.mark.parametrize("field,value,status", [
    ("retain_derived_copies", False, 400), ("retain_derived_copies", 1, 422),
    ("retain_derived_copies", "true", 422), ("actor", "user:admin", 422),
    ("tenant", "other-team", 422), ("human", True, 422),
])
def test_training_grant_needs_explicit_consent_and_rejects_body_authority(enabled, field, value, status):
    _source, run, record = accepted(enabled)
    body = {**grant_body(record), field: value}
    response = enabled.client.post(_base(run) + "/training-grant", json=body)
    assert response.status_code == status, response.text
    current = enabled.client.get(_base(run))
    assert current.json()["revision"] == record["revision"]
    assert len(enabled.calls) == 2


@pytest.mark.parametrize("receipt", [False, 1])
def test_pending_grant_withholds_signed_evidence_and_recovers_without_tool_replay(enabled, receipt):
    _source, run, record = accepted(enabled)
    original = audit.record
    enabled.monkeypatch.setattr(audit, "record", lambda *a, **kw: receipt)
    pending = enabled.client.post(_base(run) + "/training-grant", json=grant_body(record))
    assert pending.status_code == 503, pending.text
    assert PRIVATE_REF not in pending.text and RATIONALE not in pending.text
    held = enabled.client.post(_base(run) + "/signed-export", json=export_body(pending.json()))
    assert held.status_code == 503, held.text
    assert PRIVATE_REF not in held.text and "signature" not in held.text and "arguments" not in held.text
    enabled.monkeypatch.setattr(audit, "record", original)
    current = enabled.client.get(_base(run)).json()
    recovered = enabled.client.post(_base(run) + "/signed-export", json=export_body(current))
    assert recovered.status_code == 200, recovered.text
    assert len(enabled.calls) == 2


@pytest.mark.parametrize("receipt", [False, 1])
def test_pending_admission_cannot_expose_a_package_or_draft(enabled, receipt):
    _sources, value = package(enabled)
    original = audit.record
    enabled.monkeypatch.setattr(audit, "record", lambda *a, **kw: receipt)
    response = enabled.client.post(BASE, json={"package": value})
    assert response.status_code == 503, response.text
    metadata = response.json()
    assert metadata["status"] == "audit_pending" and "reference" not in metadata
    assert PRIVATE_REF not in response.text and "package" not in metadata
    for suffix in ("", "/detail"):
        held = enabled.client.get(BASE + "/" + metadata["id"] + suffix)
        assert held.status_code == 503 and PRIVATE_REF not in held.text and "package" not in held.json()
    held_draft = enabled.client.post(BASE + "/" + metadata["id"] + "/draft", json={"flow_id": "held", "name": "Held"})
    assert held_draft.status_code == 503 and PRIVATE_REF not in held_draft.text
    enabled.monkeypatch.setattr(audit, "record", original)
    resumed = enabled.client.post(BASE, json={"package": value})
    assert resumed.status_code == 200 and resumed.json()["id"] == metadata["id"]
    assert len(enabled.calls) == 4


def test_withdrawal_preserves_historical_signature_but_denies_current_admission(enabled):
    from maverick.flow.action_provenance import local_trust, verify_bundle

    sources, value = package(enabled)
    _source, run, bundle = sources[0]
    current = enabled.client.get(_base(run)).json()
    request = {"expected_revision": current["revision"], "expected_episode_sha256": current["episode_sha256"],
               "expected_review_sha256": current["review_sha256"], "withdraw": True, "rationale": "Withdraw reuse."}
    assert enabled.client.post(_base(run) + "/withdraw", json={**request, "withdraw": False}).status_code == 400
    withdrawn = enabled.client.post(_base(run) + "/withdraw", json=request)
    assert withdrawn.status_code == 200 and withdrawn.json()["status"] == "withdrawn", withdrawn.text
    with tenant_scope(tenant=TENANT):
        assert verify_bundle(bundle, trust=local_trust(TENANT), expected_tenant=TENANT,
                             now=time.time())["live_status"] == "not_checked"
    assert enabled.client.post(BASE, json={"package": value}).status_code in {400, 403, 409}
    assert len(enabled.calls) == 4


@pytest.mark.parametrize("patch", [{"actor": "user:admin"}, {"tenant": "foreign"}, {"owner": "user:admin"}])
def test_admission_body_cannot_forge_authority(enabled, patch):
    response = enabled.client.post(BASE, json={"package": {}, **patch})
    assert response.status_code == 422


def test_other_owner_and_other_owned_destination_cannot_gain_lineage(enabled):
    sources, value = package(enabled)
    assert enabled.client.post(BASE, json={"package": value}, headers={"Authorization": "Bearer bob"}).status_code == 403
    admitted = enabled.client.post(BASE, json={"package": value}).json()
    path = BASE + "/" + admitted["id"]
    assert enabled.client.get(path, headers={"Authorization": "Bearer bob"}).status_code == 403
    with tenant_scope(tenant=TENANT):
        other = copy.deepcopy(sources[0][0])
        other.id, other.owner = "foreign-destination", "user:bob"
        store.save_flow(other)
    assert enabled.client.post(path + "/draft", json={"flow_id": other.id, "name": "No"}).status_code == 403


@pytest.mark.parametrize("change", ["membership", "selection_generation", "role", "suspension", "source_owner"])
def test_lineage_service_callbacks_recheck_current_authority_after_context_creation(enabled, change):
    from maverick.tenant import registry
    from maverick_dashboard import api_flow_recipe_lineage as routes
    from maverick_dashboard import rbac, workspace_tenants

    registry.create_tenant(TENANT)
    sources, value = package(enabled)
    rbac.set_tenant_role(TENANT, OWNER, "operator")
    workspace_tenants.set_selection(OWNER, TENANT)
    request = SimpleNamespace(state=SimpleNamespace(
        principal=SimpleNamespace(principal=OWNER), workspace_tenant_source="principal_selection"))
    with tenant_scope(tenant=TENANT):
        service, ctx = routes._service(request)
        if change == "membership":
            rbac.remove_tenant_role(TENANT, OWNER)
        elif change == "selection_generation":
            workspace_tenants.set_selection(OWNER, None)
            workspace_tenants.set_selection(OWNER, TENANT)
        elif change == "role":
            rbac.set_tenant_role(TENANT, OWNER, "viewer")
        elif change == "suspension":
            registry.suspend_tenant(TENANT)
        else:
            source = sources[0][0]
            source.owner = "user:bob"
            store.save_flow(source, expected_version=source.version, expected_revision=source.revision)
        with pytest.raises((HTTPException, PermissionError)):
            service.admit(ctx, value)
    assert len(enabled.calls) == 4


def test_signed_export_does_not_accept_body_identity_or_stale_revision(enabled):
    _source, run, bundle = signed(enabled)
    current = enabled.client.get(_base(run)).json()
    body = export_body(current)
    assert enabled.client.post(_base(run) + "/signed-export", json={**body, "actor": "user:admin"}).status_code == 422
    assert enabled.client.post(_base(run) + "/signed-export", json={**body, "expected_revision": 1}).status_code == 409
    assert enabled.client.post(_base(run) + "/signed-export", json=body,
                               headers={"Authorization": "Bearer bob"}).status_code == 404
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    evidence = [event for event in events if "flow_action_episode" in json.dumps(event)]
    assert evidence and PRIVATE_REF not in json.dumps(evidence)
    assert bundle["body"]["review"]["reviewer"] == OWNER


@pytest.mark.parametrize("setting", [False, None, 1, "true"])
def test_lineage_enable_is_literal_true_and_separate_from_recipe_execution(enabled, setting):
    _source, run, record = accepted(enabled)
    enabled.flags.update(action_recipe_lineage=setting, action_recipes=True)
    response = enabled.client.post(_base(run) + "/training-grant", json=grant_body(record))
    assert response.status_code == 403, response.text
    assert len(enabled.calls) == 2


def test_lineage_http_reads_and_imports_are_tenant_scoped(enabled):
    _sources, value = package(enabled)
    admitted = enabled.client.post(BASE, json={"package": value}).json()
    enabled.monkeypatch.setenv("MAVERICK_TENANT", "other-lineage-tenant")
    for suffix in ("", "/detail"):
        response = enabled.client.get(BASE + "/" + admitted["id"] + suffix)
        assert response.status_code == 404 and PRIVATE_REF not in response.text
    response = enabled.client.post(BASE, json={"package": value})
    assert response.status_code == 403 and PRIVATE_REF not in response.text
    assert len(enabled.calls) == 4


def test_signed_source_explanation_publication_and_withdrawal(enabled):
    from maverick_dashboard import product_operations as operations
    from maverick_dashboard import product_operations_workflow_explanation as copilot

    # The dashboard app already mounts the explanation and Copilot operation
    # routes; mounting them again would leave duplicates for every later test.
    sources, value = package(enabled)
    admitted = enabled.client.post(BASE, json={"package": value}).json()
    draft = enabled.client.post(BASE + "/" + admitted["id"] + "/draft",
                                json={"flow_id": "explained", "name": "Review invoice creation"}).json()
    saved = enabled.client.post("/api/v1/flows", json={"flow": draft})
    assert saved.status_code == 201, saved.text
    path = "/api/v1/flows/explained/explanation"
    initial = enabled.client.get(path)
    assert initial.status_code == 200, initial.text
    report = initial.json()["explanation"]
    assert report["learning"]["status"] == "Allowed at this check"
    assert len(report["learning"]["examples"]) == 2
    assert report["publication"]["status"] == "Not published"
    assert report["action_approval"]["status"] == "Approval required before each learned action"
    assert all(example["permission"] == "Allowed for learning" for example in report["learning"]["examples"])
    assert "package_sha256" not in initial.text and "definition_digest" not in initial.text
    assert PRIVATE_REF not in initial.text and RATIONALE not in initial.text
    assert enabled.client.get(path, headers={"Authorization": "Bearer bob"}).status_code == 404
    enabled.monkeypatch.setattr(operations, "_gate", lambda _request: None)
    enabled.monkeypatch.setattr(operations, "_context", lambda _request: "c" * 64)
    enabled.monkeypatch.setattr(operations, "enabled_families", lambda: {"learning"})
    enabled.monkeypatch.setattr(operations, "adapters", lambda: {item.id: item for item in copilot.entries()})
    selection = {"kind": "flow", "id": "explained"}
    catalog = enabled.client.post("/api/v1/copilot/product-operations/catalog",
                                  json={"page": "/flows/designer/explained", "selection": selection}).json()
    operation = catalog["operations"][0]
    explained = enabled.client.post("/api/v1/copilot/product-operations/prepare", json={
        "page": "/flows/designer/explained", "selection": selection, "operation": operation["id"],
        "context": catalog["context"], "revision": operation["revision"], "arguments": {}})
    assert explained.status_code == 200, explained.text
    assert explained.json()["read_only"] is True
    assert explained.json()["details"]["learning"] == report["learning"]
    assert "token" not in explained.json()
    published = enabled.client.post("/api/v1/flows/explained/publish",
                                  json={"version": saved.json()["version"], "revision": saved.json()["revision"]})
    assert published.status_code == 200, published.text
    assert enabled.client.get(path).json()["explanation"]["publication"]["status"] == "Published"

    _source, source_run, _bundle = sources[0]
    current = enabled.client.get(_base(source_run)).json()
    withdrawn = enabled.client.post(_base(source_run) + "/withdraw", json={
        "expected_revision": current["revision"], "expected_episode_sha256": current["episode_sha256"],
        "expected_review_sha256": current["review_sha256"], "withdraw": True, "rationale": "Stop future reuse."})
    assert withdrawn.status_code == 200, withdrawn.text
    after = enabled.client.get(path)
    assert after.status_code == 200, after.text
    assert after.json()["explanation"]["learning"]["status"] == "Not confirmed"
    assert after.json()["explanation"]["learning"]["examples"] == []
    assert "withheld" in after.json()["explanation"]["learning"]["message"]
    with tenant_scope(tenant=TENANT):
        assert store.load_flow("explained") is not None
    assert len(enabled.calls) == 4, "reading an explanation never repeats a connected action"
