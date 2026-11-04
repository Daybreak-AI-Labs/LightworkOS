"""Startup advisory: warn when a multi-tenant deployment shares one global
channel identity. Advisory only -- it must never raise or block boot."""
from __future__ import annotations

import logging

from maverick import server as srv


class _FakeChannel:
    def __init__(self, name):
        self.name = name


class _FakeServer:
    def __init__(self, channels):
        self._channels = channels


def _set(monkeypatch, *, by_user, tenants):
    monkeypatch.setattr("maverick.paths.tenant_by_user_enabled", lambda: by_user)
    monkeypatch.setattr("maverick.tenant.registry.list_tenants", lambda: tenants)


def test_warns_when_tenant_by_user_and_channels(monkeypatch, caplog):
    _set(monkeypatch, by_user=True, tenants=[])
    server = _FakeServer([_FakeChannel("slack")])
    with caplog.at_level(logging.WARNING):
        srv._advise_channel_tenancy(server)
    assert any("share one bot identity" in r.message for r in caplog.records)


def test_warns_when_multiple_tenants_provisioned(monkeypatch, caplog):
    _set(monkeypatch, by_user=False, tenants=["acme", "globex"])
    server = _FakeServer([_FakeChannel("telegram")])
    with caplog.at_level(logging.WARNING):
        srv._advise_channel_tenancy(server)
    assert any("bot identity" in r.message for r in caplog.records)


def test_quiet_for_single_tenant(monkeypatch, caplog):
    _set(monkeypatch, by_user=False, tenants=["only"])
    server = _FakeServer([_FakeChannel("slack")])
    with caplog.at_level(logging.WARNING):
        srv._advise_channel_tenancy(server)
    assert not [r for r in caplog.records if "bot identity" in r.message]


def test_never_raises_on_error(monkeypatch):
    # A registry blow-up must not propagate out of the advisory.
    def boom():
        raise RuntimeError("registry down")
    monkeypatch.setattr("maverick.tenant.registry.list_tenants", boom)
    monkeypatch.setattr("maverick.paths.tenant_by_user_enabled", lambda: False)
    srv._advise_channel_tenancy(_FakeServer([_FakeChannel("slack")]))  # no raise
