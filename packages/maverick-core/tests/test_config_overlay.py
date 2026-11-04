from __future__ import annotations

import os
from pathlib import Path

import pytest
from maverick.config import get_sandbox, load_config


def test_config_overlay_deep_merges_without_replacing_operator_config(monkeypatch, tmp_path):
    base = tmp_path / "config.toml"
    base.write_text(
        """
[sandbox]
backend = "docker"
timeout = 42

[budget]
max_dollars = 0.25

[search]
enable = false
n = 1
""".strip(),
        encoding="utf-8",
    )
    overlay = tmp_path / "overlay.toml"
    overlay.write_text(
        """
[search]
enable = true
n = 5

[adaptive_compute]
enable = true
low_uncertainty = 0.2
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(base))
    monkeypatch.setenv("MAVERICK_CONFIG_OVERLAY", str(overlay))

    cfg = load_config()

    assert cfg["sandbox"] == {"backend": "docker", "timeout": 42}
    assert cfg["budget"] == {"max_dollars": 0.25}
    assert cfg["search"] == {"enable": True, "n": 5}
    assert cfg["adaptive_compute"] == {"enable": True, "low_uncertainty": 0.2}
    assert get_sandbox()["backend"] == "docker"


def test_explicit_load_config_path_ignores_environment_overlay(monkeypatch, tmp_path):
    base = tmp_path / "config.toml"
    base.write_text('[search]\nn = 1\n', encoding="utf-8")
    overlay = tmp_path / "overlay.toml"
    overlay.write_text('[search]\nn = 5\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG_OVERLAY", str(overlay))

    assert load_config(base) == {"search": {"n": 1}}


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length paths")
def test_active_maximum_tenant_segment_loads_its_policy_overlay(tmp_path, monkeypatch):
    from maverick.config import tenant_config_path
    from maverick.file_lock import (
        _windows_extended_path,
        atomic_write_text,
        ensure_private_directory,
    )
    from maverick.paths import MAX_TENANT_SEGMENT_LENGTH, tenant_scope

    home = tmp_path / ("h" * max(1, 90 - len(os.path.abspath(tmp_path)) - 1))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    base = tmp_path / "base.toml"
    base.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(base))
    tenant = "t" * MAX_TENANT_SEGMENT_LENGTH
    plain_overlay = home / "tenants" / tenant / "config.toml"
    assert len(os.path.abspath(plain_overlay)) > 260
    overlay = Path(_windows_extended_path(plain_overlay))
    ensure_private_directory(overlay.parent)
    atomic_write_text(overlay, "[budget]\nmax_dollars = 0.5\n")

    with tenant_scope(tenant=tenant):
        assert load_config()["budget"]["max_dollars"] == 0.5
        assert tenant_config_path() == overlay
    with tenant_scope(tenant="short"):
        assert tenant_config_path() == home / "tenants" / "short" / "config.toml"
