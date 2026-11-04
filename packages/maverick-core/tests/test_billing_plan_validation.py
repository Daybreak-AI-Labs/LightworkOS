"""Plan-name validation: a mistyped plan must not silently downgrade a tenant.

``billing.entitlements_for`` resolves an unknown plan to the ``free``
entitlements, so an operator who typos ``--plan pro`` would believe a tenant is
paid when it is not. ``known_plan_names`` + the registry/CLI warnings make that
mistake visible."""
from __future__ import annotations

import logging

from maverick import billing
from maverick.tenant import registry


def test_known_plan_names_includes_builtins():
    names = billing.known_plan_names()
    assert {"free", "pro", "enterprise"} <= names


def test_known_plan_names_picks_up_config_plans(monkeypatch):
    # known_plan_names imports load_config lazily from maverick.config; patch it
    # there so a config-defined plan is recognized alongside the built-ins.
    import maverick.config as cfg
    monkeypatch.setattr(
        cfg, "load_config",
        lambda *a, **k: {"billing": {"plans": {"gold": {"features": ["core"]}}}},
    )
    assert "gold" in billing.known_plan_names()


def test_create_tenant_warns_on_unknown_plan(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(registry, "maverick_home", lambda *a, **k: tmp_path)
    with caplog.at_level(logging.WARNING):
        rec = registry.create_tenant("acme", plan="prooo")
    assert rec.plan == "prooo"  # stored verbatim (operator may define it later)
    assert any("not a known billing plan" in m for m in caplog.messages)


def test_create_tenant_silent_on_known_plan(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(registry, "maverick_home", lambda *a, **k: tmp_path)
    with caplog.at_level(logging.WARNING):
        registry.create_tenant("beta", plan="pro")
    assert not any("not a known billing plan" in m for m in caplog.messages)
