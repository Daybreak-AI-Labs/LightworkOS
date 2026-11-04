
import pytest
from fastapi import HTTPException
from maverick_dashboard import product_operations_budget as ops


def test_preview_uses_requested_limits_without_dispatch(monkeypatch):
    seen = []
    monkeypatch.setattr(ops.native, "_projection", lambda request, **kwargs: seen.append(kwargs) or {"effective": kwargs})
    result = ops.prepare_preview(object(), {"goal_id": 8}, {"max_dollars": 2.5, "max_wall_seconds": 45.0})
    assert result.native["effective"]["max_dollars"] == 2.5
    assert seen == [{"goal_id": 8, "max_dollars": 2.5, "max_wall_seconds": 45.0}]


@pytest.mark.parametrize("identity", [True, -1, "1", 1.5])
def test_invalid_selected_task_is_not_coerced(identity):
    with pytest.raises(HTTPException):
        ops._goal_id({"goal_id": identity})


def test_help_recovery_requires_current_owner_access(monkeypatch):
    monkeypatch.setattr(ops.native, "_actor", lambda *args, **kwargs: "user:a")
    def denied(*args):
        raise HTTPException(403, "revoked")
    monkeypatch.setattr(ops.native, "_goal", denied)
    with pytest.raises(HTTPException) as error:
        ops.recover_help(object(), {"goal_id": 7}, {"provider": "example", "period": "2026-09"}, {}, "operation")
    assert error.value.status_code == 403


def test_case_operations_keep_native_revision_and_original_period(monkeypatch):
    seen = []
    row = {"revision": 6, "period": "2026-08"}
    monkeypatch.setattr(ops, "_case", lambda *args: row)
    monkeypatch.setattr(ops, "context_for", lambda request: "context")
    monkeypatch.setattr(ops.native, "progress", lambda request, identity, body: seen.append((identity, body)) or {"saved": True})
    adapter = ops._case_adapter("verify", "Verify accounting")
    review = adapter.prepare(object(), {"case_id": "BAC-own"}, {})
    adapter.execute(object(), {"case_id": "BAC-own"}, {}, review.native, "operation")
    assert seen[0][0] == "BAC-own" and seen[0][1].expected_revision == 6
    assert seen[0][1].action == "verify"
    assert row["period"] == "2026-08"
