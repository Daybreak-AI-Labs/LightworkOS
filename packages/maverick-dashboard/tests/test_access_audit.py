"""Audit rows for access changes (roles + department grants).

Every role or grant mutation writes one ``access_grant_changed`` event —
actor, target principal, field, old -> new — so who-granted-whom-what-when is
provable, not a silent JSON edit. Fail-soft is asserted structurally (a no-op
re-set emits nothing; the mutation itself is what's gated in the store tests).
"""
from __future__ import annotations

import json

import pytest

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


@pytest.fixture(autouse=True)
def _audit_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    import maverick.audit.writer as w
    monkeypatch.setattr(w, "_default", w.AuditLog(audit_dir=tmp_path / "audit"))
    yield tmp_path / "audit"


def _events(audit_dir) -> list[dict]:
    out: list[dict] = []
    if not audit_dir.exists():
        return out
    for f in sorted(audit_dir.glob("*.ndjson")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return [e for e in out if e.get("kind") == "access_grant_changed"]


def test_role_changes_are_audited(_audit_dir):
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "viewer", actor="user:boss")
    rbac.set_role("user:alice", "viewer", actor="user:boss")   # no-op: no row
    rbac.set_role("user:alice", "operator", actor="user:boss")
    rbac.remove_user("user:alice", actor="user:boss")
    ev = _events(_audit_dir)
    assert [(e["old"], e["new"]) for e in ev] == [
        (None, "viewer"), ("viewer", "operator"), ("operator", None)]
    assert all(e["actor"] == "user:boss" for e in ev)
    assert all(e["field"] == "role" and e["principal"] == "user:alice"
               for e in ev)


def test_tenant_role_changes_are_audited(_audit_dir):
    from maverick_dashboard import rbac
    rbac.set_tenant_role("acme", "user:alice", "admin", actor="user:boss")
    rbac.remove_tenant_role("acme", "user:alice", actor="user:boss")
    ev = _events(_audit_dir)
    assert [(e["field"], e["tenant"], e["old"], e["new"]) for e in ev] == [
        ("tenant_role", "acme", None, "admin"),
        ("tenant_role", "acme", "admin", None)]


def test_suite_grant_changes_are_audited(_audit_dir, monkeypatch):
    import maverick.config as config
    from maverick_dashboard import suite_grants

    # Removing an explicit grant is safe only when the configured fallback is
    # no broader than that grant.  Keep this test about the audit transition,
    # while preserving the fail-closed privilege-boundary contract.
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"dashboard": {"default_suites": ["finance"]}},
    )
    suite_grants.set_suites("user:fin", ["finance", "tax"], actor="user:boss")
    suite_grants.set_suites("user:fin", ["tax", "finance"], actor="user:boss")  # no-op
    suite_grants.remove_grant("user:fin", actor="user:boss")
    suite_grants.remove_grant("user:fin", actor="user:boss")   # already gone: no row
    ev = _events(_audit_dir)
    assert [(e["old"], e["new"]) for e in ev] == [
        (None, ["finance", "tax"]), (["finance", "tax"], None)]
    assert all(e["field"] == "suites" and e["actor"] == "user:boss"
               for e in ev)


def test_http_layer_stamps_the_acting_admin(_audit_dir, monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:boss")
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import api, auth
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:boss")
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:boss")
    c = TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert c.put("/api/v1/users/user:fin/suites",
                 json={"suites": ["finance"]}).status_code == 204
    ev = _events(_audit_dir)
    assert len(ev) == 1
    assert ev[0]["actor"] == "user:boss" and ev[0]["agent"] == "user:boss"
    assert ev[0]["principal"] == "user:fin" and ev[0]["new"] == ["finance"]
