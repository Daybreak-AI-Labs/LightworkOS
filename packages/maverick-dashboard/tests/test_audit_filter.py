"""The /audit page supports a ?kind= filter that narrows the tail to one
event kind, with a dropdown of the kinds present in the tail."""
from __future__ import annotations

import time

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _tmp_audit(monkeypatch, tmp_path):
    import maverick.audit as audit
    from maverick.audit.writer import AuditLog
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    log = AuditLog(tmp_path / "audit")
    monkeypatch.setattr(audit, "default_audit_log", lambda: log)
    from maverick.audit import reader
    monkeypatch.setattr(reader, "resolve_audit_dir", lambda tenant: log.audit_dir)
    return log


def _ev(log, kind, **payload):
    from maverick.audit.events import AuditEvent
    log.record(AuditEvent(ts=time.time(), kind=kind, payload=payload))


def test_audit_page_lists_kinds_and_filters(monkeypatch, tmp_path):
    log = _tmp_audit(monkeypatch, tmp_path)
    _ev(log, "tool_call", name="shell", input_summary="ls -la")
    _ev(log, "shield_block", stage="input", reason="jailbreak attempt")
    _ev(log, "tool_call", name="read_file", input_summary="config")

    client = _client()

    # Unfiltered: both kinds present and the filter dropdown exists.
    body = client.get("/audit").text
    assert body.count("shield_block") >= 1
    assert 'name="kind"' in body  # the dropdown

    # Filtered to shield_block: the tool_call events are gone.
    filtered = client.get("/audit?kind=shield_block").text
    assert "Stopped by the safety filter" in filtered
    assert "jailbreak attempt" not in filtered
    assert "input_summary" not in filtered  # tool_call rows filtered out


def test_audit_unknown_kind_yields_no_rows(monkeypatch, tmp_path):
    log = _tmp_audit(monkeypatch, tmp_path)
    _ev(log, "tool_call", name="shell", input_summary="ls")

    r = _client().get("/audit?kind=does_not_exist")
    assert r.status_code == 200
    assert "input_summary" not in r.text  # no matching events


def test_setting_filter_reads_deployment_chain_only_for_global_admin(monkeypatch, tmp_path):
    import maverick.audit as audit
    from maverick.audit import reader
    from maverick.audit.writer import AuditLog
    from maverick_dashboard import app as dashboard

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    local = AuditLog(tmp_path / "workspace-audit")
    deployment = AuditLog(tmp_path / "deployment-audit")
    monkeypatch.setattr(audit, "default_audit_log", lambda: local)
    monkeypatch.setattr(audit, "global_audit_log", lambda: deployment)
    monkeypatch.setattr(reader, "resolve_audit_dir", lambda _tenant: local.audit_dir)
    allowed = {"global": True}
    monkeypatch.setattr(dashboard, "has_global_permission", lambda _request, _permission: allowed["global"])
    _ev(local, "setting_changed", actor="user:workspace", section="workspace", key="workspaceonlykey", old=False, new=True)
    _ev(deployment, "setting_changed", actor="user:administrator", section="features", key="deploymentonlykey",
        old={"private": "SECRET-BEFORE"}, new={"private": "SECRET-AFTER"}, phase="completed")

    client = _client()
    global_view = client.get("/audit?kind=setting_changed")
    assert global_view.status_code == 200, global_view.text
    assert "matching deployment events" in global_view.text
    assert 'title="Recorded in the deployment-wide log' in global_view.text
    assert "deploymentonlykey" in global_view.text and "Completed" in global_view.text
    assert "workspaceonlykey" not in global_view.text
    assert "SECRET-BEFORE" not in global_view.text and "SECRET-AFTER" not in global_view.text
    assert "values before and after" in global_view.text  # metadata boundary is explicit

    allowed["global"] = False
    workspace_view = client.get("/audit?kind=setting_changed")
    assert workspace_view.status_code == 200, workspace_view.text
    assert "matching deployment events" not in workspace_view.text
    assert 'title="Recorded in the deployment-wide log' not in workspace_view.text
    assert "deployment-wide setting entries" not in workspace_view.text
    assert "workspaceonlykey" in workspace_view.text
    assert "deploymentonlykey" not in workspace_view.text


def test_incomplete_tail_is_visible_in_api_and_page(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick.file_lock import atomic_write_bytes
    from maverick_dashboard import app as dash_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    log = _tmp_audit(monkeypatch, tmp_path)
    atomic_write_bytes(log.audit_dir / "2020-01-01.ndjson", b'{"kind":"tool_call"}\n{"torn":')
    with TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        response = client.get("/api/v1/audit/tail?day=2020-01-01")
        assert response.status_code == 200
        assert response.json()["read_report"]["state"] == "partial"
        page = client.get("/audit?day=2020-01-01")
        assert page.status_code == 200
        assert "This view is incomplete" in page.text
