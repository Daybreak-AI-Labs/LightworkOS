"""A change to a tenant's billing terms (plan / daily cap) must leave a
tamper-evident audit row, so an upgrade or cap change is provable rather than a
silent control-plane edit."""
from __future__ import annotations

import maverick.audit.writer as _writer
import pytest
from maverick.audit import iter_events
from maverick.tenant import registry


@pytest.fixture(autouse=True)
def _isolate_home_and_audit(tmp_path, monkeypatch):
    """Point HOME at a tmp dir AND reset the cached default audit-log singleton,
    which resolves its directory once from HOME — otherwise record() writes to
    the import-time home while reads use the tmp one (test-only; HOME is stable
    in production)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(_writer, "_default", None)
    monkeypatch.setattr(_writer, "_defaults", {})
    yield


def _tenant_rows(kind_prefix="tenant_"):
    return [e for e in iter_events() if str(e.get("kind", "")).startswith(kind_prefix)]


def test_set_plan_emits_signed_audit_row():
    registry.create_tenant("acme", plan="free")
    registry.set_plan("acme", "enterprise")
    rows = [e for e in _tenant_rows() if e["kind"] == "tenant_plan_changed"]
    assert len(rows) == 1
    e = rows[0]
    assert e["tenant"] == "acme" and e["field"] == "plan"
    assert e["old"] == "free" and e["new"] == "enterprise"


def test_set_quota_emits_audit_row():
    registry.create_tenant("beta", plan="free", max_daily_dollars=10.0)
    registry.set_quota("beta", 50.0)
    rows = [e for e in _tenant_rows() if e["kind"] == "tenant_quota_changed"]
    assert len(rows) == 1
    e = rows[0]
    assert e["tenant"] == "beta" and e["field"] == "quota"
    assert e["old"] == 10.0 and e["new"] == 50.0


def test_no_billing_audit_without_a_change():
    registry.create_tenant("gamma", plan="free")
    # create alone must not emit a plan/quota *change* row
    assert not _tenant_rows()
