"""Plan-tier feature entitlement enforcement.

``billing.feature_allowed`` is the enforcement-side gate wired into the channel
serve path (``channels``) and the SIEM audit export (``audit_export``). It must
stay permissive at the edges -- single-tenant and unprovisioned per-user tenant
ids are never denied -- so only an explicitly provisioned, limited plan bites.
"""
from __future__ import annotations

import pytest
from maverick import billing
from maverick.paths import reset_tenant, set_tenant
from maverick.tenant import registry as tr


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    tok = set_tenant(None)
    yield
    reset_tenant(tok)


def test_no_active_tenant_is_allowed():
    # Single-tenant / self-host: nothing to gate.
    assert billing.feature_allowed("channels") is True
    assert billing.feature_allowed("audit_export") is True


def test_unprovisioned_tenant_is_allowed():
    # A per-user tenant id with no registry entry must not be denied (this is
    # the default MAVERICK_TENANT_BY_USER path -- breaking it would break serve).
    assert billing.feature_allowed("channels", tenant="slack:U123") is True
    assert billing.feature_allowed("audit_export", tenant="slack:U123") is True


def test_registered_free_plan_is_denied_paid_features():
    tr.create_tenant("acme", plan="free")
    assert billing.feature_allowed("channels", tenant="acme") is False
    assert billing.feature_allowed("audit_export", tenant="acme") is False
    # ...but the base feature it does hold is allowed.
    assert billing.feature_allowed("core", tenant="acme") is True


def test_registered_paid_plans_are_allowed():
    tr.create_tenant("pro-co", plan="pro")
    tr.create_tenant("ent-co", plan="enterprise")
    assert billing.feature_allowed("channels", tenant="pro-co") is True
    # audit_export is an enterprise-only entitlement by default.
    assert billing.feature_allowed("audit_export", tenant="pro-co") is False
    assert billing.feature_allowed("audit_export", tenant="ent-co") is True


def test_resolves_active_tenant_from_context():
    tr.create_tenant("acme", plan="free")
    tok = set_tenant("acme")
    try:
        # No explicit tenant arg -> resolves the active ContextVar tenant.
        assert billing.feature_allowed("channels") is False
    finally:
        reset_tenant(tok)
    # Scope restored -> no tenant -> allowed again.
    assert billing.feature_allowed("channels") is True
