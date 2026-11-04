"""Personal test metadata erasure never permits repeat provider admission."""
from copy import deepcopy

import pytest
from maverick import model_test_retention as service
from maverick import model_tests


@pytest.fixture
def history(monkeypatch, tmp_path):
    monkeypatch.setattr(model_tests, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(service, "current_tenant_id_strict", lambda: "workspace")
    monkeypatch.setattr(service, "audit_event", lambda *args, **kwargs: True)
    context = service._context("user:a")
    row = {"id": "one", "state": "passed", "model": "private-route", "route": {"secret_config": "private"}, "binding": "private", "limits": {"max_wall_seconds": 30}}
    model_tests._edit(context, lambda checks: checks.update(one=deepcopy(row)))
    model_tests._edit(service._context("user:b"), lambda checks: checks.update(other={**row, "id": "other"}))
    return context


def test_erasure_keeps_nonreplay_tombstone_and_other_owner(history):
    preview = service.owned_inventory("user:a")
    outcome = service.erase_owned("user:a", expected_version=preview["version"], actor="user:reviewer", operation_id="request")
    assert outcome == {"status": "confirmed", "removed": 1}
    row = model_tests.get(history, "one")
    assert row["state"] == "erased" and "route" not in row and "model" not in row
    saved, claimed = model_tests.claim(history, "one", lambda: None)
    assert saved["state"] == "erased" and claimed is False
    assert service.owned_inventory("user:a")["count"] == 0
    assert service.export_owned("user:b")["checks"][0]["model"] == "private-route"
    assert service.erase_owned("user:a", expected_version=preview["version"], actor="user:reviewer", operation_id="request")["status"] == "confirmed"


@pytest.mark.parametrize("state", ["queued", "executing", "unknown", "unrecognized"])
def test_active_or_uncertain_receipts_block_erasure(history, state):
    model_tests._edit(history, lambda checks: checks["one"].update(state=state))
    preview = service.owned_inventory("user:a")
    assert preview["blocked"] == 1
    with pytest.raises(ValueError, match="Reconcile"):
        service.erase_owned("user:a", expected_version=preview["version"], actor="user:reviewer", operation_id="request")
    assert model_tests.get(history, "one")["state"] == state


def test_stale_review_and_missing_start_receipt_do_not_erase(history, monkeypatch):
    preview = service.owned_inventory("user:a")
    model_tests._edit(history, lambda checks: checks["one"].update(message="new"))
    with pytest.raises(ValueError, match="changed"):
        service.erase_owned("user:a", expected_version=preview["version"], actor="user:reviewer", operation_id="request")
    monkeypatch.setattr(service, "audit_event", lambda *args, **kwargs: False)
    with pytest.raises(RuntimeError, match="acknowledged"):
        service.erase_owned("user:a", expected_version=service.owned_inventory("user:a")["version"], actor="user:reviewer", operation_id="request")
    assert model_tests.get(history, "one")["model"] == "private-route"


def test_final_audit_failure_reports_unconfirmed_without_repeat(history, monkeypatch):
    monkeypatch.setattr(service, "audit_event", lambda kind, **kwargs: kind.endswith("started"))
    outcome = service.erase_owned("user:a", expected_version=service.owned_inventory("user:a")["version"], actor="user:reviewer", operation_id="request")
    assert outcome["status"] == "unconfirmed"
    assert model_tests.get(history, "one")["state"] == "erased"
    assert model_tests.claim(history, "one", lambda: None)[1] is False
