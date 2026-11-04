"""Deployment halt scope is shared by API and dashboard surfaces."""
from __future__ import annotations

import pytest
from maverick import config, world_model_backends
from maverick_dashboard.halt_policy import shared_halt_backend


def test_unreadable_config_never_becomes_local_halt(monkeypatch):
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "config_source_errors", lambda: ["unavailable"])
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: False)
    with pytest.raises(RuntimeError, match="unavailable"):
        shared_halt_backend()


@pytest.mark.parametrize("shared", [True, False])
def test_halt_scope_uses_the_configured_backend(monkeypatch, shared):
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: shared)
    assert shared_halt_backend() is shared
