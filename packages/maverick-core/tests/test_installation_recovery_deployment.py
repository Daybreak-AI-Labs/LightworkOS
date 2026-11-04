"""Whole-home recovery cannot inherit one tenant's narrower storage view."""
from __future__ import annotations

import pytest
from maverick import config, file_lock, installation_recovery, paths


@pytest.mark.parametrize(("shared", "tenant"), [
    ('[knowledge]\nstore = "postgres"\n', '[knowledge]\nstore = "sqlite"\n'),
    ('[knowledge]\npath = "external-data.db"\n', '[knowledge]\npath = ""\n'),
    ('[grpc_dispatch]\ntarget = "worker.example.invalid:8443"\n', '[grpc_dispatch]\ntarget = ""\n'),
    ('redis = "shared-service"\n', 'redis = ""\n'),
    ('qdrant = "shared-service"\n', 'qdrant = ""\n'),
    ('pgvector = "shared-service"\n', 'pgvector = ""\n'),
])
def test_shared_external_storage_cannot_be_hidden_by_ambient_tenant(tmp_path, monkeypatch, shared, tenant):
    home = file_lock.ensure_private_directory(tmp_path / "deployment")
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    monkeypatch.setenv("MAVERICK_TENANT", "local-team")
    monkeypatch.delenv(config.CONFIG_OVERLAY_ENV, raising=False)
    file_lock.atomic_write_text(home / "config.toml", shared)
    tenant_home = file_lock.ensure_private_directory(home / "tenants" / "local-team")
    file_lock.atomic_write_text(tenant_home / "config.toml", tenant)
    token = paths.set_tenant(None)
    try:
        reasons = installation_recovery.blockers()
    finally:
        paths.reset_tenant(token)
    assert reasons, "a whole-home operation must retain shared deployment storage blockers"


def test_shared_local_defaults_remain_eligible():
    assert installation_recovery._shared_blockers({}) == []
    assert installation_recovery._shared_blockers({
        "kms": {"provider": "local"}, "world_model": {"backend": "sqlite"},
        "governed_records": {"backend": "local"}, "memory": {"backend": "auto"},
        "knowledge": {"store": "sqlite"}, "grpc_dispatch": {"target": ""},
    }) == []
