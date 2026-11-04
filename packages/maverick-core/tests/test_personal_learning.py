"""Reviewed generated-tool deletion never discloses names or broadens source CAS."""
from types import SimpleNamespace

import pytest
from maverick import personal_learning as service


def test_review_metadata_omits_private_generated_names(monkeypatch):
    monkeypatch.setattr(service, "owned_tools", lambda owner: [{"id": "opaque", "digest": "d", "name": "acquisition_customer", "goal_id": 9}])
    targets = service.reviewed_targets("user:a")
    assert targets == [{"id": "opaque", "digest": "d", "goal_id": 9}]
    assert "acquisition_customer" not in repr(targets)


def test_exact_review_digest_reaches_locked_native_delete(monkeypatch):
    calls = []
    row = {"id": "opaque", "digest": "d", "name": "private_name", "goal_id": 9}
    monkeypatch.setattr(service, "owned_tools", lambda owner: [row])
    monkeypatch.setattr(service.self_learning, "delete_generated_tool", lambda name, **kw: calls.append((name, kw)))
    result = service.erase_reviewed("user:a", service.reviewed_targets("user:a"), actor="user:reviewer")
    assert calls == [("private_name", {"actor": "user:reviewer", "owner": "user:a", "expected_digest": "d"})]
    assert result["state"] == "purged"
    assert "private_name" not in repr(result)


def test_changed_source_rejects_before_any_removal(monkeypatch):
    monkeypatch.setattr(service, "owned_tools", lambda owner: [{"id": "changed", "digest": "d2", "name": "private", "goal_id": 9}])
    monkeypatch.setattr(service.self_learning, "delete_generated_tool", lambda *a, **kw: pytest.fail("must not dispatch"))
    with pytest.raises(ValueError, match="changed"):
        service.erase_reviewed("user:a", [{"id": "old", "digest": "d1", "goal_id": 9}], actor="user:reviewer")


def test_inventory_lineage_does_not_claim_all_derived_data_removed(monkeypatch):
    monkeypatch.setattr(service, "owned_tools", lambda owner: [])
    monkeypatch.setattr(service.self_learning, "history", lambda **kw: [SimpleNamespace(goal_id=4, kind="tool", ts=10)])
    result = service.inventory("user:a")
    assert result["learning_records"] == [{"goal_id": 4, "kind": "tool", "date": 10}]
    assert result["state"] == "current-authorized-only"
    assert "does not certify" in result["limits"]
