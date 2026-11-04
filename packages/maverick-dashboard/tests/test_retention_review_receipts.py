"""Retention preview/receipt safety regressions, authored for later execution."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from maverick_dashboard import retention_runs
from maverick_dashboard.compliance_controls_api import _summarize_retention


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(retention_runs, "_scope", lambda: ("a", [{
        "tenant": "a", "name": "Workspace A", "policy": {"messages_days": 30, "events_days": 90}}]))
    from maverick import audit
    monkeypatch.setattr(audit, "audit_event", lambda *_, **__: True)


def test_locked_or_error_report_never_claims_nothing_old_enough():
    for report in ({"audit": {"removed": [], "skipped": ["old-day"]}}, {"store": {"error": "locked"}}):
        summary = _summarize_retention(report)
        assert summary["unresolved"] is True
        assert "Nothing was old enough" not in summary["message"]


def test_policy_change_invalidates_review(isolated, monkeypatch):
    from maverick.audit import retention
    monkeypatch.setattr(retention, "enforce", lambda **_: {"messages": {"deleted": 2}})
    review = retention_runs.preview("user:admin")
    monkeypatch.setattr(retention_runs, "_scope", lambda: ("b", []))
    with pytest.raises(HTTPException) as error:
        retention_runs.apply(review["id"], "user:admin", confirm_holds=True, retry=False, authorize=lambda: None)
    assert error.value.status_code == 409


def test_retry_skips_completed_store_and_preserves_unknown_receipt(isolated, monkeypatch):
    from maverick.audit import retention
    def enforce(**kw):
        if kw.get("dry_run"):
            return {"messages": {"deleted": 2}, "goal_events": {"deleted": 1}}
        if "events_days" in kw["config"]:
            raise OSError("store unavailable")
        return {"messages": {"deleted": 2}, "marker": {"messages_deleted": 2}}
    monkeypatch.setattr(retention, "enforce", enforce)
    review = retention_runs.preview("user:admin")
    result = retention_runs.apply(review["id"], "user:admin", confirm_holds=True, retry=False, authorize=lambda: None)
    assert result["status"] == "partial"
    calls = []
    def retry(**kw):
        calls.append(kw["config"])
        return {"goal_events": {"deleted": 0}}
    monkeypatch.setattr(retention, "enforce", retry)
    result = retention_runs.apply(review["id"], "user:admin", confirm_holds=True, retry=True, authorize=lambda: None)
    assert calls == [{"events_days": 90}]
    assert result["status"] == "partial"  # prior ambiguous deletion cannot become proven zero
    assert retention_runs.read(review["id"], "user:admin")["steps"][0]["removed"] == 2


def test_audit_failure_never_dispatches_deletion(isolated, monkeypatch):
    from maverick import audit
    from maverick.audit import retention
    calls = []
    monkeypatch.setattr(retention, "enforce", lambda **kw: calls.append(kw) or {})
    review = retention_runs.preview("user:admin")
    calls.clear()
    monkeypatch.setattr(audit, "audit_event", lambda *_, **__: False)
    with pytest.raises(HTTPException) as error:
        retention_runs.apply(review["id"], "user:admin", confirm_holds=True, retry=False, authorize=lambda: None)
    assert error.value.status_code == 503
    assert calls == []


def test_internal_hold_cannot_be_overridden_by_confirmation(isolated, monkeypatch):
    from maverick.audit import retention
    monkeypatch.setattr(retention_runs, "_scope", lambda: ("a", [{
        "tenant": "a", "name": "A", "policy": {"messages_days": 30},
        "preservation": {"blocked": True, "legal_holds": 1}}]))
    calls = []
    monkeypatch.setattr(retention, "enforce", lambda **kw: calls.append(kw) or {})
    review = retention_runs.preview("user:admin")
    assert review["blocked_by_hold"]
    calls.clear()
    with pytest.raises(HTTPException) as error:
        retention_runs.apply(review["id"], "user:admin", confirm_holds=True, retry=False, authorize=lambda: None)
    assert error.value.status_code == 409
    assert calls == []


def test_revocation_at_fence_blocks_effect(isolated, monkeypatch):
    from maverick.audit import retention
    calls = []
    monkeypatch.setattr(retention, "enforce", lambda **kw: calls.append(kw) or {})
    review = retention_runs.preview("user:admin")
    calls.clear()
    checks = 0
    def authorize():
        nonlocal checks
        checks += 1
        # Checks: after reading, before recording acceptance, before the step,
        # and at the deletion fence itself. Revoke at the fence.
        if checks == 4:
            raise HTTPException(403, "Role removed")
    with pytest.raises(HTTPException):
        retention_runs.apply(review["id"], "user:admin", confirm_holds=True, retry=False, authorize=authorize)
    assert calls == []
    assert retention_runs.read(review["id"], "user:admin")["steps"][0]["status"] == "blocked"
