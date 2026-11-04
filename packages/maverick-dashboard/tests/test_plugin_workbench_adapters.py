"""Local native/Copilot workbench authorization and no-replay regressions."""
from __future__ import annotations

import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick import plugin_execution_pins as pins
from maverick import plugin_workbench as workbench
from maverick.flow import store
from maverick_dashboard import plugin_workbench_api as native
from maverick_dashboard import product_operations_plugins as copilot


@pytest.fixture
def native_scope(monkeypatch, tmp_path):
    from maverick_dashboard import flows_api
    monkeypatch.setattr(pins, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(native, "_authority", lambda *args: None)
    monkeypatch.setattr(native, "caller_principal", lambda request: "alice")
    monkeypatch.setattr(store, "run_lock", lambda run_id: nullcontext())
    run = SimpleNamespace(run_id="run-1", flow_id="flow-1", owner="alice", status="paused_approval", definition_revision="r1")
    monkeypatch.setattr(store, "load_run", lambda ident, **kwargs: run if kwargs.get("owner") == run.owner else None)
    monkeypatch.setattr(store, "load_flow", lambda ident: SimpleNamespace(owner="alice"))
    monkeypatch.setattr(flows_api, "_can_access_flow", lambda request, flow: True)
    current = {"group": "maverick.tools", "name": "tool", "distribution": "plugin", "content_sha256": "b" * 64}
    monkeypatch.setattr(workbench, "selected", lambda fingerprint: current)
    monkeypatch.setattr(workbench, "history", lambda context: {"publications": [{"fingerprint": "c" * 64, "current": True}]})
    with pins.flow_scope("run-1", "alice", "r1"):
        pins.check_pin("maverick.tools", "tool", "plugin", "a" * 64)
    return run


def body():
    return native.MigrateFlowIn(context="f" * 64, run_id="run-1", fingerprint="c" * 64, previous="a" * 64, confirm=True)


def test_flow_migration_changes_only_stopped_exact_owner_pin(native_scope):
    result = native.migrate_flow_plugin_pin(None, body())
    assert result == {"migrated": True, "workflow_resumed": False, "historical_actions_replayed": False}
    row = json.loads(pins.flow_path("run-1").read_text(encoding="utf-8"))["plugin:tool"]
    assert row["fingerprint"] == "b" * 64 and row["prior_fingerprints"] == ["a" * 64]
    assert native_scope.status == "paused_approval"
    with pytest.raises(HTTPException) as error:
        native.migrate_flow_plugin_pin(None, body())
    assert error.value.status_code == 409


@pytest.mark.parametrize("state", ["running", "resuming", "indeterminate"])
def test_flow_migration_rejects_active_or_unknown_work(native_scope, state):
    native_scope.status = state
    with pytest.raises(HTTPException) as error:
        native.migrate_flow_plugin_pin(None, body())
    assert error.value.status_code == 409
    assert json.loads(pins.flow_path("run-1").read_text(encoding="utf-8"))["plugin:tool"]["fingerprint"] == "a" * 64


def test_flow_migration_never_substitutes_other_owner(native_scope):
    native_scope.owner = "bob"
    with pytest.raises(HTTPException) as error:
        native.migrate_flow_plugin_pin(None, body())
    assert error.value.status_code == 404


def test_copilot_recovers_existing_unknown_check_without_dispatch(monkeypatch):
    monkeypatch.setattr(native, "_authority", lambda *args: None)
    row = {"id": "1" * 32, "state": "running_or_interrupted"}
    monkeypatch.setattr(workbench, "history", lambda context: {"checks": [row]})
    monkeypatch.setattr(workbench, "run_check", lambda *args, **kwargs: pytest.fail("an uncertain check must never be replayed"))
    result = copilot.check(None, {}, {}, {"context": "f" * 64}, "1" * 32)
    assert result.status == "replayed" and result.details["state"] == "running_or_interrupted"


def test_copilot_rechecks_native_authority_before_receipt_disclosure(monkeypatch):
    def revoked(*args):
        raise HTTPException(403, "revoked")
    monkeypatch.setattr(native, "_authority", revoked)
    monkeypatch.setattr(workbench, "history", lambda context: pytest.fail("must not read private ledger after revocation"))
    with pytest.raises(HTTPException) as error:
        copilot.recover_check(None, {}, {}, {"context": "f" * 64}, "1" * 32)
    assert error.value.status_code == 403


def test_flow_migration_operation_is_durable_and_recovers_same_receipt(native_scope):
    reviewed = body().model_copy(update={"operation_id": "7" * 32})
    first = native.migrate_flow_plugin_pin(None, reviewed)
    second = native.migrate_flow_plugin_pin(None, reviewed)
    assert first == second
    row = json.loads(pins.flow_path("run-1").read_text(encoding="utf-8"))["plugin:tool"]
    assert row["prior_fingerprints"] == ["a" * 64]
    assert row["migration_operations"]["7" * 32] == {"previous": "a" * 64, "current": "b" * 64}
