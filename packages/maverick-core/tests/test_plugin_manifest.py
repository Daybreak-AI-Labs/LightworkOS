"""Tests for plugin manifests (maverick.plugin_manifest)."""
from __future__ import annotations

import pytest

# ---------- plugin_manifest ----------

def test_plugin_manifest_parse_minimal_valid():
    from maverick.plugin_manifest import MAVERICK_API_VERSION, parse_dict
    m = parse_dict({
        "plugin": {
            "name": "x",
            "version": "0.1.0",
            "api_version": MAVERICK_API_VERSION,
        }
    })
    assert m is not None
    assert m.name == "x"
    assert m.is_compatible()


def test_plugin_manifest_missing_required_field():
    from maverick.plugin_manifest import parse_dict
    m = parse_dict({"plugin": {"name": "x", "version": "0.1.0"}})  # no api_version
    assert m is None


def test_plugin_manifest_incompatible_version_warns():
    from maverick.plugin_manifest import parse_dict
    m = parse_dict({
        "plugin": {
            "name": "x", "version": "0.1.0",
            "api_version": "999",
        }
    })
    assert m is not None
    assert not m.is_compatible()
    assert any("api_version" in w for w in m.warnings)


@pytest.mark.parametrize("api_version", ["1", "1.0", "01", "1.5"])
def test_plugin_manifest_compatible_by_major(api_version):
    # Kernel is v2 with a v1 deprecation window; any plugin with major 1
    # stays compatible (loaded with a deprecation warning) regardless of how
    # its api_version string is spelled.
    from maverick.plugin_manifest import parse_dict
    m = parse_dict({
        "plugin": {"name": "x", "version": "0.1.0", "api_version": api_version}
    })
    assert m is not None
    assert m.is_compatible()
    assert m.is_deprecated_api()
    assert not any("not in supported majors" in w for w in m.warnings)


@pytest.mark.parametrize("api_version", ["3", "0", "abc", "v1"])
def test_plugin_manifest_incompatible_by_major(api_version):
    from maverick.plugin_manifest import parse_dict
    m = parse_dict({
        "plugin": {"name": "x", "version": "0.1.0", "api_version": api_version}
    })
    assert m is not None
    assert not m.is_compatible()
    assert any("api_version" in w for w in m.warnings)


def test_plugin_manifest_loads_capabilities_permissions():
    from maverick.plugin_manifest import MAVERICK_API_VERSION, parse_dict
    m = parse_dict({
        "plugin": {
            "name": "x", "version": "0.1.0",
            "api_version": MAVERICK_API_VERSION,
            "capabilities": {
                "tools": ["my_tool", "other"],
                "channels": ["telegram"],
            },
            "permissions": {
                "network": True, "fs_write": False,
                "sensitive_envs": ["MY_API_KEY"],
            },
        }
    })
    assert m is not None
    assert m.capabilities.tools == ["my_tool", "other"]
    assert m.capabilities.channels == ["telegram"]
    assert m.permissions.network is True
    assert m.permissions.fs_write is False
    assert m.permissions.sensitive_envs == ["MY_API_KEY"]


def test_plugin_manifest_parse_file(tmp_path):
    from maverick.plugin_manifest import MAVERICK_API_VERSION, parse
    f = tmp_path / "maverick-plugin.toml"
    f.write_text(
        f'[plugin]\nname = "x"\nversion = "0.1.0"\n'
        f'api_version = "{MAVERICK_API_VERSION}"\n'
    )
    m = parse(f)
    assert m is not None
    assert m.name == "x"


def test_plugin_manifest_parse_missing_file(tmp_path):
    from maverick.plugin_manifest import parse
    assert parse(tmp_path / "nope.toml") is None
