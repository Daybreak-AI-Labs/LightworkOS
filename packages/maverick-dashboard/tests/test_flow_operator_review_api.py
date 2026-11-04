"""Native review storage behind authenticated flow ownership and tenant gates."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import config, world_model
from maverick.flow import store
from maverick.flow.evolve import attach_learned_operator
from maverick.flow.ir import Flow, FlowNode
from maverick.flow.learned_operator import synthesize
from maverick.oidc import VerifiedPrincipal
from maverick.paths import tenant_scope
from maverick_dashboard import auth


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", "review-team")
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(config, "get_flows", lambda: {
        "enable": True, "learned_operator_questions": True,
    })
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "is_dashboard_admin", lambda actor: actor == "user:admin")
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **kw: VerifiedPrincipal(
        sub=token, issuer="https://issuer.example", audience="maverick", claims={"sub": token},
    ))
    from maverick_dashboard import rbac
    from maverick_dashboard.app import app

    monkeypatch.setattr(rbac, "default_role", lambda: "operator")
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1",
                                    "Authorization": "Bearer alice"})


def _save(flow_id="f", *, tenant="review-team", owner="user:alice", composed=False):
    spec = {
        "inputs": {"x": {"type": "integer", "min": 0, "max": 10}},
        "output_type": "boolean", "constants": [5],
    }
    examples = [{"inputs": {"x": 0}, "output": False}, {"inputs": {"x": 10}, "output": True}]
    if composed:
        from maverick.flow.composed_operator import synthesize as compose

        artifact = compose(spec, examples, max_operations=2, operators=["lt", "le", "if"])
    else:
        artifact = synthesize(spec, examples)
    flow = Flow(id=flow_id, name="Review", start="compute", owner=owner,
                nodes={"compute": FlowNode(id="compute", kind="agent",
                                           brief="Return whether x is above five", output="result")})
    with tenant_scope(tenant=tenant):
        return store.save_flow(attach_learned_operator(flow, "compute", artifact))


def _request(client, flow, **extra):
    return client.post(f"/api/v1/flows/{flow.id}/operator-questions", json={
        "node_id": "compute", "version": flow.version, "revision": flow.revision,
        **extra,
    })


def _answer(record, **extra):
    return {"expected_revision": record["revision"], "output": False,
            "reviewed": True, "rationale": "Reviewed the threshold boundary against the rule.",
            **extra}


@pytest.mark.parametrize("composed", [False, True])
def test_review_lifecycle_records_authenticated_reviewer_without_saving_or_publishing(client, composed):
    flow = _save(composed=composed)
    response = _request(client, flow)
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["status"] == "awaiting_answer"
    assert record["question"]["inputs"] == {"x": 5}
    base = f"/api/v1/flows/f/operator-questions/{record['id']}"
    assert client.get(base).json()["requested_by"] == "user:alice"
    response = client.post(base + "/answer", json=_answer(record))
    assert response.status_code == 200, response.text
    answered = response.json()
    assert answered["status"] == "draft_ready"
    assert answered["review"]["reviewer"] == "user:alice"
    assert answered["review"]["output"] is False
    exported = client.get(base + "/draft")
    assert exported.status_code == 200, exported.text
    assert exported.json()["saved"] is False and exported.json()["published"] is False
    assert exported.json()["flow"]["owner"] == "user:alice"
    with tenant_scope(tenant="review-team"):
        assert store.load_flow("f").to_dict() == flow.to_dict()
        assert store.load_published_bundle("f") is None


def test_static_bearer_cannot_supply_a_reviewer_identity(client, monkeypatch):
    flow = _save()
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "shared-test-token")
    client.headers["Authorization"] = "Bearer shared-test-token"
    response = _request(client, flow)
    assert response.status_code == 401, response.text
    assert "authenticated user identity" in response.json()["detail"]


def test_other_owner_cannot_read_or_answer_review(client):
    flow = _save()
    response = _request(client, flow)
    assert response.status_code == 200, response.text
    record = response.json()
    base = f"/api/v1/flows/f/operator-questions/{record['id']}"
    headers = {"Authorization": "Bearer bob"}
    assert client.get(base, headers=headers).status_code == 404
    assert client.post(base + "/answer", json=_answer(record), headers=headers).status_code == 404
    assert client.get(base + "/draft", headers=headers).status_code == 404


def test_viewer_and_disabled_feature_refused(client, monkeypatch):
    flow = _save()
    from maverick_dashboard import rbac

    monkeypatch.setattr(rbac, "default_role", lambda: "viewer")
    assert _request(client, flow).status_code == 403
    monkeypatch.setattr(rbac, "default_role", lambda: "operator")
    monkeypatch.setattr(config, "get_flows", lambda: {"enable": True})
    assert _request(client, flow).status_code == 403


def test_review_id_cannot_be_used_under_other_flow_or_tenant(client, monkeypatch):
    flow = _save()
    record = _request(client, flow).json()
    _save("other")
    base = f"/api/v1/flows/other/operator-questions/{record['id']}"
    assert client.get(base).status_code == 404
    assert client.post(base + "/answer", json=_answer(record)).status_code == 404
    _save(tenant="other-team")
    monkeypatch.setenv("MAVERICK_TENANT", "other-team")
    base = f"/api/v1/flows/f/operator-questions/{record['id']}"
    assert client.get(base).status_code == 404


def test_per_principal_isolation_needs_no_selected_workspace_membership(client, monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT")
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    flow = _save(tenant="api:user:alice")
    response = _request(client, flow)
    assert response.status_code == 200, response.text
    assert response.json()["requested_by"] == "user:alice"


def test_source_revision_and_answer_revision_conflicts(client):
    flow = _save()
    assert _request(client, flow, revision="stale-generation").status_code == 409
    record = _request(client, flow).json()
    base = f"/api/v1/flows/f/operator-questions/{record['id']}"
    response = client.post(base + "/answer", json=_answer(record, expected_revision=99))
    assert response.status_code == 409
    with tenant_scope(tenant="review-team"):
        changed = flow.copy()
        changed.name = "Edited after question"
        store.save_flow(changed, expected_version=flow.version, expected_revision=flow.revision)
    assert client.post(base + "/answer", json=_answer(record)).status_code == 409
    historical = client.get(base)
    assert historical.status_code == 200, historical.text
    assert historical.json()["source_current"] is False
    assert "draft" not in historical.json() and "refined_artifact" not in historical.json()
    assert client.get(base + "/draft").status_code == 409


@pytest.mark.parametrize("patch", [
    {"reviewer": "user:admin"}, {"tenant": "other"}, {"reviewed": "true"},
    {"output": 0.5}, {"output": None}, {"expected_revision": True},
])
def test_answer_rejects_identity_spoofing_and_scalar_coercion(client, patch):
    record = _request(client, _save()).json()
    response = client.post(f"/api/v1/flows/f/operator-questions/{record['id']}/answer",
                           json=_answer(record, **patch))
    assert response.status_code == 422, response.text


def test_explicit_review_is_required(client):
    record = _request(client, _save()).json()
    response = client.post(f"/api/v1/flows/f/operator-questions/{record['id']}/answer",
                           json=_answer(record, reviewed=False))
    assert response.status_code == 400


def test_committed_pending_audit_is_reported_and_export_blocked(client, monkeypatch):
    from maverick import audit

    record = _request(client, _save()).json()
    base = f"/api/v1/flows/f/operator-questions/{record['id']}"
    original_record = audit.record
    monkeypatch.setattr(audit, "record", lambda *a, **kw: False)
    response = client.post(base + "/answer", json=_answer(record))
    assert response.status_code == 503, response.text
    pending = response.json()
    assert pending["status"] == "audit_pending"
    assert pending["committed_status"] == "draft_ready"
    assert "draft" not in pending and "refined_artifact" not in pending
    assert client.get(base + "/draft").status_code == 503
    monkeypatch.setattr(audit, "record", original_record)
    recovered = client.get(base)
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["revision"] == pending["revision"]
    assert recovered.json()["audit_status"] == "delivered"
    assert client.get(base + "/draft").status_code == 200


@pytest.mark.parametrize("change", ["membership", "selection_generation", "suspension"])
def test_workspace_authority_revalidated_after_question_computation(client, monkeypatch, change):
    from types import SimpleNamespace

    from maverick.flow import operator_queries
    from maverick.tenant import registry
    from maverick_dashboard import api_flow_operator_review as routes
    from maverick_dashboard import rbac, workspace_tenants

    registry.create_tenant("review-team")
    flow = _save()
    rbac.set_tenant_role("review-team", "user:alice", "operator")
    workspace_tenants.set_selection("user:alice", "review-team")
    request = SimpleNamespace(state=SimpleNamespace(
        principal=SimpleNamespace(principal="user:alice"),
        workspace_tenant_source="principal_selection",
    ))
    original = operator_queries.propose_question

    def change_authority(artifact, *, max_probes=256):
        question = original(artifact, max_probes=max_probes)
        if change == "membership":
            rbac.remove_tenant_role("review-team", "user:alice")
        elif change == "selection_generation":
            workspace_tenants.set_selection("user:alice", None)
            workspace_tenants.set_selection("user:alice", "review-team")
        else:
            registry.suspend_tenant("review-team")
        return question

    monkeypatch.setattr(operator_queries, "propose_question", change_authority)
    with tenant_scope(tenant="review-team"):
        service, ctx = routes._service(request, flow.id)
        with pytest.raises(HTTPException) as rejected:
            service.request(ctx, flow.id, "compute", expected_flow_version=flow.version,
                            expected_flow_revision=flow.revision)
        assert rejected.value.status_code in {403, 409}
        assert service.records.list() == []
