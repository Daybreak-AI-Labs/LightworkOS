"""Deprecation registry + sunset gate."""
from __future__ import annotations

import warnings

import pytest
from maverick import deprecations as dep


@pytest.fixture(autouse=True)
def _fresh():
    dep.reset_warned()
    yield
    dep.reset_warned()


def test_registry_entries_well_formed():
    assert dep.REGISTRY, "registry should carry the live deprecations"
    for d in dep.REGISTRY:
        assert d.name and d.kind and d.target and d.replacement
        assert dep._vtuple(d.remove_in) > dep._vtuple(d.deprecated_in)


def test_warn_once_emits_exactly_once():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        dep.warn_once("plugins.api_v1")
        dep.warn_once("plugins.api_v1")
    msgs = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert len(msgs) == 1
    assert "REMOVED in" in str(msgs[0].message)


def test_warn_once_unregistered_never_raises():
    dep.warn_once("not.a.real.entry")  # logs, no exception


def test_past_due_by_version():
    assert dep.past_due("0.1.6") == []          # nothing due yet
    due = dep.past_due("0.3.0")                  # the v1 window closes at 0.3.0
    assert {d.name for d in due} >= {"plugins.api_v1", "channels.str_handler"}
    assert dep.past_due("9.9.9") == list(dep.REGISTRY)


def test_vtuple_parses_loose_versions():
    assert dep._vtuple("0.3.0") == (0, 3, 0)
    # a pre-release tag keeps the major.minor ordering usable
    assert dep._vtuple("1.2.3rc1")[:2] == (1, 2)
    assert dep._vtuple("") == (0,)


def test_current_version_reuses_package_version():
    import maverick

    assert dep.current_version() == maverick.__version__


def test_check_config_reports_config_kind(monkeypatch):
    fake = dep.Deprecation(
        name="x.old_knob", kind="config", target="[tools] old_knob",
        replacement="[tools] new_knob", deprecated_in="0.1.0", remove_in="0.9.0")
    monkeypatch.setattr(dep, "REGISTRY", (fake,))
    assert dep.check_config({"tools": {"old_knob": True}})
    assert dep.check_config({"tools": {"new_knob": True}}) == []
    assert dep.check_config({}) == []


def test_render_marks_past_due(monkeypatch):
    monkeypatch.setattr(dep, "current_version", lambda: "9.9.9")
    out = dep.render()
    assert "PAST DUE" in out


def test_render_no_past_due_at_current(monkeypatch):
    monkeypatch.setattr(dep, "current_version", lambda: "0.1.6")
    out = dep.render()
    assert "PAST DUE" not in out


def test_plugin_manifest_v1_warns_via_registry():
    from maverick.plugin_manifest import parse_dict
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        parse_dict({"plugin": {"name": "p", "version": "1", "api_version": "1"}})
    assert any("REMOVED in 0.3.0" in str(w.message) for w in caught)


def test_channel_str_shim_warns_via_registry():
    import importlib.util
    if importlib.util.find_spec("maverick_channels") is None:
        pytest.skip("maverick-channels not installed")
    from maverick_channels.base import as_reply
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        as_reply("bare string")
    assert any("Reply" in str(w.message) for w in caught)
