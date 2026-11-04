"""Local registry contracts, with native effect/provider seams injected."""
from contextlib import nullcontext
from dataclasses import replace

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick_dashboard import product_operations as ops


class Value(ops.StrictInput):
    value: str


@pytest.fixture
def registry(monkeypatch):
    state = {"revision": "1", "context": "a" * 64, "calls": 0, "receipt": None, "allowed": True}
    codec = Fernet(Fernet.generate_key())
    monkeypatch.setattr(ops, "_same_origin", lambda request: None)
    monkeypatch.setattr(ops, "_gate", lambda request: None)
    monkeypatch.setattr(ops, "_context", lambda request: state["context"])
    monkeypatch.setattr(ops, "enabled_families", lambda: {"preferences"})
    monkeypatch.setattr(ops.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + codec.encrypt(value.encode()).decode())
    monkeypatch.setattr(ops.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(ops.crypto_at_rest, "unseal_from_str", lambda value: codec.decrypt(value[7:].encode()).decode())
    from maverick import authority_effects
    monkeypatch.setattr(authority_effects, "authority_effect_fence", nullcontext)
    def snapshot(request, selection):
        if not state["allowed"]:
            raise HTTPException(403, "denied")
        return ops.Snapshot(state["revision"], "Saved preference", "Current source", {"value": "old"})
    def execute(request, selection, args, native, operation):
        state["calls"] += 1
        state["receipt"] = operation
        state["revision"] = "2"
        return ops.Outcome("confirmed", "saved", {"value": args["value"]})
    def recover(request, selection, args, native, operation):
        return ops.Outcome("replayed", "already saved") if state["receipt"] == operation else None
    adapter = ops.Adapter("preferences.example", "Example", "preferences", "/preferences", ("/preferences",), Value,
                          snapshot, lambda req, sel, args: ops.Preview("Review", [{"before": "old", "after": args["value"]}]), execute, recover,
                          read_recovery=recover)
    state["adapter"] = adapter
    monkeypatch.setattr(ops, "adapters", lambda: {adapter.id: state["adapter"]})
    app = FastAPI()
    app.include_router(ops.router)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client, state


BASE = "/api/v1/copilot/product-operations"


def prepare(client, state, **changes):
    body = {"page": "/preferences", "selection": {}, "operation": "preferences.example",
            "context": state["context"], "revision": "1", "arguments": {"value": "new"}}
    body.update(changes)
    return client.post(BASE + "/prepare", json=body)


def test_review_does_not_execute_and_native_receipt_recovers_exact_retry(registry):
    client, state = registry
    review = prepare(client, state)
    assert review.status_code == 200 and state["calls"] == 0
    payload = {"token": review.json()["token"], "confirmed": True}
    completed = client.post(BASE + "/execute", json=payload).json()
    assert completed["status"] == "confirmed" and completed["message"] == "saved"
    assert client.post(BASE + "/execute", json=payload).json()["status"] == "replayed"
    assert state["calls"] == 1


def test_original_outcome_read_never_dispatches_even_without_receipt(registry):
    client, state = registry
    review = prepare(client, state).json()
    assert review["recovery_available"] is True
    reference = {"token": review["token"]}
    assert client.post(BASE + "/recover", json=reference).json()["status"] == "unconfirmed"
    assert state["calls"] == 0
    state["adapter"] = replace(state["adapter"], read_recovery=None)
    assert client.post(BASE + "/recover", json=reference).json()["status"] == "unconfirmed"
    assert state["calls"] == 0
    state["adapter"] = replace(state["adapter"], read_recovery=state["adapter"].recover)
    client.post(BASE + "/execute", json={**reference, "confirmed": True})
    assert client.post(BASE + "/recover", json=reference).json()["status"] == "replayed"
    assert state["calls"] == 1
    state["allowed"] = False
    assert client.post(BASE + "/recover", json=reference).status_code == 403
    assert state["calls"] == 1


@pytest.mark.parametrize("change", ["confirmation", "tampered", "context", "revision", "access"])
def test_unreviewed_stale_or_foreign_context_never_mutates(registry, change):
    client, state = registry
    payload = {"token": prepare(client, state).json()["token"], "confirmed": True}
    if change == "confirmation":
        payload["confirmed"] = False
    elif change == "tampered":
        payload["token"] = payload["token"][:-7] + "changed"
    elif change == "context":
        state["context"] = "b" * 64
    elif change == "revision":
        state["revision"] = "updated"
    else:
        state["allowed"] = False
    assert client.post(BASE + "/execute", json=payload).status_code in {400, 403, 409}
    assert state["calls"] == 0


def test_proposal_reads_adapters_off_the_event_loop(registry, monkeypatch):
    """A slow adapter snapshot must stall one worker thread, not the dashboard."""
    import asyncio

    client, state = registry
    monkeypatch.setattr(ops, "_read_gate", lambda request: None)
    seen = []
    plain = state["adapter"].snapshot

    def snapshot(request, selection):
        try:
            asyncio.get_running_loop()
            seen.append("event loop")
        except RuntimeError:
            seen.append("worker thread")
        return plain(request, selection)

    state["adapter"] = replace(state["adapter"], snapshot=snapshot)
    response = client.post(BASE + "/propose", json={
        "page": "/preferences", "selection": {}, "context": state["context"], "message": "Example"})
    assert response.status_code == 200 and response.json()["operation"] == "preferences.example"
    assert seen and set(seen) == {"worker thread"}


def test_model_or_client_cannot_supply_handler_authority_or_extra_arguments(registry):
    client, state = registry
    assert prepare(client, state, arguments={"value": "new", "actor": "admin"}).status_code == 422
    assert prepare(client, state, operation="shell.execute").status_code == 404
    assert prepare(client, state, page="https://outside.invalid").status_code == 422
    assert state["calls"] == 0


def test_readonly_prepared_comparison_and_bounded_source_failure(registry):
    client, state = registry
    state["adapter"] = replace(state["adapter"], execute=None, prepare=lambda *args: ops.Preview("Compared", native={"requested": 5}))
    result = prepare(client, state).json()
    assert result["read_only"] and result["details"] == {"requested": 5} and "token" not in result
    def fail(*args): raise ValueError("private details must not escape")
    state["adapter"] = replace(state["adapter"], snapshot=fail)
    response = client.post(BASE + "/catalog", json={"page": "/preferences"})
    assert response.status_code == 200 and response.json()["operations"][0]["available"] is False
    assert "private details" not in response.text


def test_snapshot_rechecks_before_readonly_publication(registry):
    client, state = registry
    def changed(*args):
        state["revision"] = "new"
        return ops.Preview("Outdated")
    state["adapter"] = replace(state["adapter"], execute=None, prepare=changed)
    assert prepare(client, state).status_code == 409


def test_catalog_does_not_release_previous_context_information(registry):
    client, state = registry
    def changed(request, selection):
        state["context"] = "b" * 64
        return ops.Snapshot("1", "Private source", "Earlier access", {"private": "old-account-content"})
    state["adapter"] = replace(state["adapter"], snapshot=changed)
    response = client.post(BASE + "/catalog", json={"page": "/preferences"})
    assert response.status_code == 409
    assert "old-account-content" not in response.text


def test_no_department_access_and_unrestricted_access_have_distinct_contexts(monkeypatch):
    from starlette.requests import Request
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    monkeypatch.setattr(ops, "context_for", lambda request: "same-account-workspace")
    monkeypatch.setattr(ops.auth, "caller_role", lambda request: "admin")
    monkeypatch.setattr(ops.auth, "has_global_permission", lambda request, permission: True)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"preferences"})
    monkeypatch.setattr(ops.auth, "caller_suites", lambda request: None)
    unrestricted = ops._context(request)
    monkeypatch.setattr(ops.auth, "caller_suites", lambda request: set())
    assert ops._context(request) != unrestricted


def test_the_access_digest_follows_the_account_not_the_permitted_action_families(monkeypatch):
    # The context binds reviews to the permitted actions too; the access
    # digest says whether the person's account or access changed.
    from starlette.requests import Request
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    monkeypatch.setattr(ops, "context_for", lambda request: "same-account-workspace")
    monkeypatch.setattr(ops.auth, "caller_role", lambda request: "admin")
    monkeypatch.setattr(ops.auth, "has_global_permission", lambda request, permission: True)
    monkeypatch.setattr(ops.auth, "caller_suites", lambda request: None)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"preferences"})
    context, access = ops._context(request), ops._access(request)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"preferences", "tasks"})
    assert ops._context(request) != context and ops._access(request) == access
    monkeypatch.setattr(ops.auth, "caller_role", lambda request: "operator")
    assert ops._access(request) != access


def test_the_catalog_carries_the_access_digest(registry, monkeypatch):
    client, state = registry
    monkeypatch.setattr(ops, "_access", lambda request: "c" * 64)
    assert client.post(BASE + "/catalog", json={"page": "/preferences"}).json()["access"] == "c" * 64


def test_a_catalog_read_while_the_account_changes_is_refused_not_mixed(registry, monkeypatch):
    # The person's role changes while the controls are read: the response
    # must not pair the earlier context with the later access digest.
    client, state = registry
    reads = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(ops, "_access", lambda request: next(reads, "b" * 64))
    assert client.post(BASE + "/catalog", json={"page": "/preferences"}).status_code == 409
