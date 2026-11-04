"""Audit-only learning activity must not expose old private lesson payloads."""
from types import SimpleNamespace

from maverick import audit
from maverick_dashboard import learning_loop_api


def test_learning_activity_drops_free_text_before_return(monkeypatch):
    rows = [{"kind": audit.EventKind.LEARNING_UPDATE, "agent": "self_harness", "ts": 3,
             "phase": "employee private phase", "model_id": "private model payload", "line": "employee private lesson"}]
    monkeypatch.setattr(audit, "default_audit_log", lambda: SimpleNamespace(tail=lambda count: rows))
    assert learning_loop_api._log_rows(20) == [{"when": 3, "what": "Learning activity", "model": "", "lesson": ""}]
