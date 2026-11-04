"""Actual authenticated native evidence withdrawal via a closed operating catalog.

OIDC signature verification is stubbed by the isolated native fixture. Source
ownership, workspace context, encryption, capture, human review, CAS and audit
are real. LLM responses are injected only at the existing provider seam.
"""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest
from maverick import audit, config
from maverick.flow import store
from maverick.paths import tenant_scope
from maverick_dashboard import copilot_operations as operations

from test_support.action_episode_api import PRIVATE_REF, TENANT, _accepted, _base
from test_support.action_episode_api import harness as harness

BASE = "/api/v1/copilot/operations"


def _setup(harness):
    harness.monkeypatch.setattr(config, "get_features", lambda: {"copilot_operations": True})
    source, run, _record = _accepted(harness)
    selection = {"kind": "flow_run", "flow_id": run.flow_id, "run_id": run.run_id}
    response = harness.client.get(BASE, params={"flow_id": run.flow_id, "run_id": run.run_id})
    assert response.status_code == 200, response.text
    return source, run, selection, response.json()


def _prepare(harness, selection, catalog):
    response = harness.client.post(BASE + "/prepare", json={
        "selection": selection, "operation_id": operations.WITHDRAW, "expected_scope": catalog["scope"]})
    assert response.status_code == 200, response.text
    return response.json()


def _execute_body(selection, prepared):
    return {"selection": selection, "operation_id": operations.WITHDRAW, "scope": prepared["scope"],
            "token": prepared["token"], "confirmed": True, "rationale": "Reviewed stop-use decision."}


def test_native_catalog_prepare_confirm_withdraw_and_exact_retry(harness):
    _source, run, selection, catalog = _setup(harness)
    calls = copy.deepcopy(harness.calls)
    assert catalog["record"]["status"] == "accepted"
    assert catalog["record"]["withdrawal_available"] is True
    assert {item["id"] for item in catalog["operations"]} == {operations.STATUS, operations.WITHDRAW}
    prepared = _prepare(harness, selection, catalog)
    assert prepared["record"] == catalog["record"]
    assert harness.client.get(_base(run) + "/withdrawal").json()["status"] == "accepted"
    body = _execute_body(selection, prepared)
    response = harness.client.post(BASE + "/execute", json=body)
    assert response.status_code == 200, response.text
    assert response.json()["outcome"] == "confirmed"
    assert response.json()["record"]["status"] == "withdrawn"
    assert response.json()["record"]["revision"] == catalog["record"]["revision"] + 1
    retry = harness.client.post(BASE + "/execute", json=body)
    assert retry.status_code == 200 and retry.json()["record"] == response.json()["record"]
    assert harness.calls == calls
    for value in (catalog, prepared, response.json()):
        encoded = json.dumps(value)
        assert PRIVATE_REF not in encoded
        for forbidden in ("episode_sha256", "review_sha256", "rationale_sha256", "request_sha256", "sensitive_envelope"):
            assert forbidden not in encoded


@pytest.mark.parametrize("mode", ["disabled", "engine", "halt"])
def test_operation_flag_is_separate_from_native_maintenance(harness, mode):
    _source, run, selection, catalog = _setup(harness)
    if mode == "disabled":
        harness.monkeypatch.setattr(config, "get_features", lambda: {"copilot_operations": False})
        response = harness.client.get(BASE, params={"flow_id": run.flow_id, "run_id": run.run_id})
        assert response.status_code == 403
        assert harness.client.get(_base(run) + "/withdrawal").status_code == 200
        return
    if mode == "engine":
        harness.flags.update(enable=False, action_episode_capture=False, action_recipe_lineage=False)
        harness.monkeypatch.setenv("MAVERICK_FLOWS", "0")
    else:
        from maverick import learning_guard
        harness.monkeypatch.setattr(learning_guard, "learning_write_allowed", lambda *a, **kw: False)
    prepared = _prepare(harness, selection, catalog)
    response = harness.client.post(BASE + "/execute", json=_execute_body(selection, prepared))
    assert response.status_code == 200 and response.json()["outcome"] == "confirmed"


@pytest.mark.parametrize("change", ["unconfirmed", "truthy", "blank", "token", "scope", "selection", "extra"])
def test_malformed_or_unreviewed_requests_never_withdraw(harness, change):
    _source, run, selection, catalog = _setup(harness)
    body = _execute_body(selection, _prepare(harness, selection, catalog))
    if change == "unconfirmed":
        body["confirmed"] = False
    elif change == "truthy":
        body["confirmed"] = 1
    elif change == "blank":
        body["rationale"] = "  "
    elif change == "token":
        body["token"] = body["token"][:-3] + "bad"
    elif change == "scope":
        body["scope"] = "0" * 64
    elif change == "selection":
        body["selection"]["flow_id"] = "other-flow"
    else:
        body["actor"] = "user:admin"
    response = harness.client.post(BASE + "/execute", json=body)
    assert response.status_code in {400, 403, 404, 409, 422}, response.text
    assert harness.client.get(_base(run) + "/withdrawal").json()["status"] == "accepted"


def test_current_actor_and_role_are_rechecked_for_prepare_and_execute(harness):
    _source, run, selection, catalog = _setup(harness)
    prepared = _prepare(harness, selection, catalog)
    for endpoint, payload in [
        ("prepare", {"selection": selection, "operation_id": operations.WITHDRAW, "expected_scope": catalog["scope"]}),
        ("execute", _execute_body(selection, prepared)),
    ]:
        response = harness.client.post(BASE + "/" + endpoint, json=payload,
                                       headers={"Authorization": "Bearer admin"})
        # Ownership checks may conceal inaccessible operations before the
        # operation-level context check runs.
        assert response.status_code in {404, 409}
        if response.status_code == 409:
            assert response.json()["detail"]["code"] == "operation_context_changed"
    other = harness.client.get(BASE, params={"flow_id": run.flow_id, "run_id": run.run_id},
                               headers={"Authorization": "Bearer bob"})
    assert other.status_code in {403, 404} and "record" not in other.json()
    from maverick_dashboard import rbac
    harness.monkeypatch.setattr(rbac, "default_role", lambda: "viewer")
    denied = harness.client.post(BASE + "/execute", json=_execute_body(selection, prepared))
    assert denied.status_code == 403


def test_replaced_same_id_source_invalidates_preparation(harness):
    source, _run, selection, catalog = _setup(harness)
    prepared = _prepare(harness, selection, catalog)
    with tenant_scope(tenant=TENANT):
        store.delete_flow(source.id)
        source.version = 0
        store.save_flow(source)
    response = harness.client.post(BASE + "/execute", json=_execute_body(selection, prepared))
    assert response.status_code == 409


def test_pending_receipt_never_claims_success_and_readback_recovers_without_replay(harness):
    _source, run, selection, catalog = _setup(harness)
    prepared = _prepare(harness, selection, catalog)
    calls = copy.deepcopy(harness.calls)
    original = audit.record
    harness.monkeypatch.setattr(audit, "record", lambda *a, **kw: 1)
    response = harness.client.post(BASE + "/execute", json=_execute_body(selection, prepared))
    assert response.status_code == 503, response.text
    assert response.json()["outcome"] == "audit_pending"
    assert response.json()["record"]["committed_status"] == "withdrawn"
    pending = harness.client.get(BASE, params={"flow_id": run.flow_id, "run_id": run.run_id})
    assert pending.status_code == 503 and pending.json()["record"]["withdrawal_available"] is False
    harness.monkeypatch.setattr(audit, "record", original)
    refreshed = harness.client.get(BASE, params={"flow_id": run.flow_id, "run_id": run.run_id})
    assert refreshed.status_code == 200 and refreshed.json()["record"]["status"] == "withdrawn"
    assert refreshed.json()["record"]["revision"] == catalog["record"]["revision"] + 1
    assert harness.calls == calls


def test_prepare_scope_expiry_and_same_origin_are_enforced(harness):
    _source, run, selection, catalog = _setup(harness)
    request = {"selection": selection, "operation_id": operations.WITHDRAW, "expected_scope": "0" * 64}
    assert harness.client.post(BASE + "/prepare", json=request).status_code == 409
    prepared = _prepare(harness, selection, catalog)
    body = _execute_body(selection, prepared)
    assert harness.client.post(BASE + "/execute", json=body, headers={"Origin": "https://other.example"}).status_code == 403
    harness.monkeypatch.setattr(operations.time, "time", lambda: prepared["expires_at"] + 1)
    assert harness.client.post(BASE + "/execute", json=body).status_code == 409
    assert harness.client.get(_base(run) + "/withdrawal").json()["status"] == "accepted"


def test_provider_free_exact_intent_only_proposes_and_yes_is_not_consent(harness):
    _source, run, selection, catalog = _setup(harness)
    from maverick_dashboard import _shared
    harness.monkeypatch.setattr(_shared, "_any_provider_key_set", lambda: False)
    for message, expected in [("Stop using this example", operations.WITHDRAW), ("status", operations.STATUS),
                              ("yes", None), ("Do not stop using this example", None)]:
        response = harness.client.post(BASE + "/propose", json={
            "selection": selection, "expected_scope": catalog["scope"], "message": message})
        assert response.status_code == 200, response.text
        assert response.json()["proposal"] == {"operation_id": expected, "source": "built_in"}
        assert "token" not in response.text
    assert harness.client.get(_base(run) + "/withdrawal").json()["status"] == "accepted"


@pytest.mark.parametrize("output", [
    '{"operation_id":"learning_example.withdraw"}',
    '{"operation_id":"learning_example.withdraw","confirmed":true}',
    '{"operation_id":"shell.run"}', '{"operation_id":null,"operation_id":"learning_example.withdraw"}',
    'I withdrew the example.',
])
def test_model_is_a_closed_proposal_parser_and_never_gets_private_context(harness, output):
    _source, run, selection, catalog = _setup(harness)
    from maverick import llm
    from maverick_dashboard import _shared
    captured = {}

    class Model:
        def __init__(self, _spec):
            pass

        def complete(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(text=output)

    harness.monkeypatch.setattr(_shared, "_any_provider_key_set", lambda: True)
    harness.monkeypatch.setattr(_shared, "require_provider_or_400", lambda **kw: None)
    harness.monkeypatch.setattr(llm, "LLM", Model)
    response = harness.client.post(BASE + "/propose", json={
        "selection": selection, "expected_scope": catalog["scope"], "message": "Please retire this learning example."})
    assert response.status_code == 200, response.text
    valid = output == '{"operation_id":"learning_example.withdraw"}'
    assert response.json()["proposal"] == {"operation_id": operations.WITHDRAW if valid else None,
                                           "source": "model" if valid else "built_in_fallback"}
    assert "tools" not in captured and captured["budget"].max_tool_calls == 0
    assert PRIVATE_REF not in str(captured) and run.run_id not in str(captured)
    assert catalog["scope"] not in str(captured)
    assert harness.client.get(_base(run) + "/withdrawal").json()["status"] == "accepted"
