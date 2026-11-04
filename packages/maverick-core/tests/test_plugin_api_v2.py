"""Plugin API v2 release: version bump + v1 deprecation window."""
from __future__ import annotations

from maverick import plugin_manifest as pm


def _manifest(api_version: str):
    return pm.parse_dict({
        "plugin": {
            "name": "p", "version": "0.1.0", "api_version": api_version,
            "license": "MIT", "author": "a",
        }
    })


def test_kernel_is_v2_and_supports_v1_window():
    assert pm.MAVERICK_API_VERSION == "2"
    assert pm.SUPPORTED_API_MAJORS == (1, 2)


def test_v2_plugin_compatible_no_deprecation():
    m = _manifest("2")
    assert m.is_compatible() is True
    assert m.is_deprecated_api() is False
    assert m.warnings == []


def test_v1_plugin_loads_with_deprecation_warning():
    m = _manifest("1")
    assert m.is_compatible() is True       # the deprecation window
    assert m.is_deprecated_api() is True
    assert any("deprecated" in w for w in m.warnings)


def test_v3_plugin_refused():
    m = _manifest("3")
    assert m.is_compatible() is False
    assert any("not in supported majors" in w for w in m.warnings)


def test_minor_versions_map_to_major():
    assert _manifest("1.4").is_compatible() is True
    assert _manifest("2.0").is_deprecated_api() is False


def test_malformed_api_version_refused():
    m = _manifest("two")
    assert m.is_compatible() is False
    assert m.is_deprecated_api() is False
