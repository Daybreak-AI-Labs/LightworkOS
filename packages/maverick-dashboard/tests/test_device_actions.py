"""No-network reviewed-device authority, stale-source and receipt tests."""
import json
import sys
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick_dashboard import device_actions as actions
from maverick_dashboard import device_pairing as pairing
from pydantic import BaseModel, ConfigDict
from starlette.requests import Request


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


@pytest.fixture
def native(monkeypatch):
    state = {"revision": "b" * 64, "context": "a" * 64, "effects": 0, "receipt": None}
    def execute(*args):
        state["effects"] += 1
        state["receipt"] = SimpleNamespace(status="confirmed", message="Stop requested", details={}, background=None)
        state["revision"] = "c" * 64
        return state["receipt"]
    adapter = SimpleNamespace(input_model=Arguments,
        snapshot=lambda *args: SimpleNamespace(revision=state["revision"], blocked=""),
        prepare=lambda *args: SimpleNamespace(summary="Review Stop", changes=[], native={"expected_updated_at": 1.0}),
        recover=lambda *args: state["receipt"], execute=execute)
    monkeypatch.setattr(actions, "authority_effect_fence", nullcontext)
    monkeypatch.setattr(actions, "_adapter", lambda action: adapter)
    monkeypatch.setattr(actions, "_require_device", lambda request: state["context"])
    monkeypatch.setattr(actions.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + value)
    monkeypatch.setattr(actions.crypto_at_rest, "unseal_from_str", lambda value: value[7:])
    monkeypatch.setattr(actions.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setitem(sys.modules, "maverick_dashboard.app", SimpleNamespace(_require_same_origin=lambda request: None))
    return state


def request():
    return Request({"type": "http", "method": "POST", "path": "/api/v1/devices/actions/execute", "headers": []})


def reviewed():
    response = actions.prepare(request(), actions.Prepare(goal_id=1, action="stop", context="a" * 64, revision="b" * 64))
    return json.loads(response.body)["token"]


def test_prepare_has_no_effect_and_explicit_confirmation_is_required(native):
    token = reviewed()
    assert native["effects"] == 0
    with pytest.raises(HTTPException) as error:
        actions.execute(request(), actions.Execute(token=token, confirmed=False))
    assert error.value.status_code == 400 and native["effects"] == 0


def test_exact_receipt_recovers_before_source_freshness_without_repeating(native):
    token = reviewed()
    actions.execute(request(), actions.Execute(token=token, confirmed=True))
    actions.execute(request(), actions.Execute(token=token, confirmed=True))
    assert native["effects"] == 1


@pytest.mark.parametrize("changed", ["revision", "context"])
def test_review_rejects_task_or_device_change(native, changed):
    token = reviewed()
    native[changed] = "d" * 64
    with pytest.raises(HTTPException) as error:
        actions.execute(request(), actions.Execute(token=token, confirmed=True))
    assert error.value.status_code == 409 and native["effects"] == 0


def test_expired_review_cannot_apply_even_with_current_authority(native, monkeypatch):
    token = reviewed()
    monkeypatch.setattr(actions.time, "time", lambda: 10**12)
    with pytest.raises(HTTPException):
        actions.execute(request(), actions.Execute(token=token, confirmed=True))
    assert native["effects"] == 0


@pytest.mark.parametrize("device,policy", [(False, True), (True, False), (False, False)])
def test_action_route_requires_both_enrollment_and_current_policy(device, policy):
    for method, path in [("GET", "context"), ("POST", "prepare"), ("POST", "execute")]:
        with pytest.raises(HTTPException):
            pairing._scope(method, "/api/v1/devices/actions/" + path, {"actions": device}, {"actions": policy})
    pairing._scope("POST", "/api/v1/devices/actions/execute", {"actions": True}, {"actions": True})


def test_device_identity_is_reauthenticated_for_each_operation(monkeypatch):
    current = request()
    current.state.paired_device_id = "a" * 32
    monkeypatch.setattr(actions.auth, "_bearer_token", lambda request: "synthetic")
    def revoked(*args):
        raise HTTPException(401, "Revoked")
    monkeypatch.setattr(pairing, "authenticate", revoked)
    with pytest.raises(HTTPException) as error:
        actions._require_device(current)
    assert error.value.status_code == 401
