"""Plugin load-time enforcement: name-squat defense + manifest permissions.

Complements test_plugins.py (discovery semantics and the allowlist). Here we
pin the two controls layered on the allowlist:

  - a name published by 2+ distributions is refused unless pinned `name@dist`,
  - a plugin whose maverick-plugin.toml requests an ungranted permission is
    skipped (the default) or, with enforce_permissions=false, loaded+warned.
"""
from __future__ import annotations

import logging

import pytest
from maverick import plugins
from maverick.plugin_manifest import parse_text


class _FakeFile:
    def __init__(self, name: str, text: str):
        self.name = name
        self._text = text

    def read_text(self, encoding: str = "utf-8") -> str:
        return self._text


class _FakeDist:
    def __init__(self, name: str, manifest_text: str | None = None):
        self.name = name
        self._manifest_text = manifest_text

    @property
    def files(self):
        if self._manifest_text is None:
            return []
        return [_FakeFile("maverick-plugin.toml", self._manifest_text)]


class _FakeEP:
    def __init__(self, name, target, dist=None):
        self.name = name
        self.target = target
        self.dist = dist

    def load(self):
        if isinstance(self.target, Exception):
            raise self.target
        return self.target


def _set_eps(monkeypatch, mapping):
    monkeypatch.setattr(plugins, "_entry_points", lambda group: mapping.get(group, []))


def _manifest_toml(**perms) -> str:
    body = '[plugin]\nname = "p"\nversion = "1.0"\napi_version = "1"\n[plugin.permissions]\n'
    for k, v in perms.items():
        if isinstance(v, bool):
            body += f"{k} = {'true' if v else 'false'}\n"
        elif isinstance(v, list):
            body += f"{k} = [{', '.join(repr(x) for x in v)}]\n"
    return body


@pytest.fixture(autouse=True)
def _hermetic_plugins_config(monkeypatch):
    # No grant; enforce-by-default (the secure default). Tests that need the
    # warn-only path set enforce_permissions=false explicitly.
    monkeypatch.setattr(plugins, "_plugins_config", dict)
    monkeypatch.delenv("MAVERICK_PLUGINS_ENFORCE", raising=False)


# ---------- name-squat defense ----------

def test_ambiguous_name_refused_even_under_wildcard(monkeypatch):
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("weather", lambda: "trusted", dist=_FakeDist("trusted-weather")),
        _FakeEP("weather", lambda: "EVIL", dist=_FakeDist("evil-pkg")),
    ]})
    # A name backed by two distributions can't be loaded unambiguously.
    assert plugins.discover_tools() == []


def test_pinning_resolves_the_squat(monkeypatch):
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "weather@trusted-weather")
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("weather", lambda: "trusted", dist=_FakeDist("trusted-weather")),
        _FakeEP("weather", lambda: "EVIL", dist=_FakeDist("evil-pkg")),
    ]})
    out = plugins.discover_tools()
    assert len(out) == 1
    name, factory = out[0]
    assert name == "weather"
    assert factory() == "trusted"   # the evil same-named provider never loads


def test_single_provider_with_dist_loads_normally(monkeypatch):
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "weather")
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("weather", lambda: "ok", dist=_FakeDist("weather-pkg")),
    ]})
    assert [n for n, _ in plugins.discover_tools()] == ["weather"]


# ---------- manifest permission gate ----------

def test_ungranted_permission_skipped_when_enforced(monkeypatch):
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.setattr(plugins, "_plugins_config", lambda: {"enforce_permissions": True})
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("wp", lambda: "ok", dist=_FakeDist("wp", _manifest_toml(network=True))),
    ]})
    assert plugins.discover_tools() == []   # network requested, not granted, enforced


def test_ungranted_permission_skipped_by_default(monkeypatch):
    # The default is enforce -- a manifest requesting an ungranted
    # permission is NOT loaded. (Manifest-less plugins declare none -> see
    # test_unmanifested_plugin_loads_even_when_enforced.)
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")  # default _plugins_config -> {} (enforce)
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("wp", lambda: "ok", dist=_FakeDist("wp", _manifest_toml(network=True))),
    ]})
    assert plugins.discover_tools() == []  # network requested, not granted -> skipped


def test_ungranted_permission_warns_when_enforce_disabled(monkeypatch, caplog):
    # The escape hatch: enforce_permissions=false reverts to load-with-warning.
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.setattr(plugins, "_plugins_config",
                        lambda: {"enforce_permissions": False})
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("wp", lambda: "ok", dist=_FakeDist("wp", _manifest_toml(network=True))),
    ]})
    with caplog.at_level(logging.WARNING, logger="maverick.plugins"):
        out = plugins.discover_tools()
    assert [n for n, _ in out] == ["wp"]            # loaded
    assert "not in [plugins] grant" in caplog.text  # but warned


def test_granted_permission_loads_under_enforcement(monkeypatch):
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.setattr(
        plugins, "_plugins_config",
        lambda: {"grant": ["network"], "enforce_permissions": True},
    )
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("wp", lambda: "ok", dist=_FakeDist("wp", _manifest_toml(network=True))),
    ]})
    assert [n for n, _ in plugins.discover_tools()] == ["wp"]


def test_unmanifested_plugin_loads_even_when_enforced(monkeypatch):
    # No manifest => no declared permissions => nothing to enforce. Keeps the
    # large body of existing manifest-less plugins working under enforcement.
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.setattr(plugins, "_plugins_config", lambda: {"enforce_permissions": True})
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("plain", lambda: "ok", dist=_FakeDist("plain-pkg")),
    ]})
    assert [n for n, _ in plugins.discover_tools()] == ["plain"]


def test_enforce_env_override(monkeypatch):
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.setenv("MAVERICK_PLUGINS_ENFORCE", "1")
    # config explicitly disables enforcement...
    monkeypatch.setattr(plugins, "_plugins_config",
                        lambda: {"enforce_permissions": False})
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("wp", lambda: "ok", dist=_FakeDist("wp", _manifest_toml(subprocess=True))),
    ]})
    assert plugins.discover_tools() == []   # ...but the env var forces enforce back on


def test_enforce_env_can_disable(monkeypatch, caplog):
    # MAVERICK_PLUGINS_ENFORCE=0 downgrades the default enforce to warn-only.
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.setenv("MAVERICK_PLUGINS_ENFORCE", "0")
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("wp", lambda: "ok", dist=_FakeDist("wp", _manifest_toml(network=True))),
    ]})
    with caplog.at_level(logging.WARNING, logger="maverick.plugins"):
        out = plugins.discover_tools()
    assert [n for n, _ in out] == ["wp"]  # loaded (enforcement disabled via env)


# ---------- advisory: permissions unenforced under isolation 'none' ---------

def test_advisory_warning_when_granted_but_isolation_none(monkeypatch, caplog):
    # A plugin DECLARES network, the operator GRANTS it, so it loads -- but
    # isolation 'none' (the default) runs it in-process, so the grant is only
    # advisory. Warn so the operator knows it isn't runtime-enforced.
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.setattr(
        plugins, "_plugins_config",
        lambda: {"grant": ["network"], "enforce_permissions": True},
    )
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("wp", lambda: "ok", dist=_FakeDist("wp", _manifest_toml(network=True))),
    ]})
    with caplog.at_level(logging.WARNING, logger="maverick.plugins"):
        out = plugins.discover_tools()
    assert [n for n, _ in out] == ["wp"]          # loaded (granted)
    assert "ADVISORY" in caplog.text              # ...but flagged as advisory
    assert "isolation" in caplog.text.lower()


def test_advisory_warns_even_when_enforce_disabled(monkeypatch, caplog):
    # enforce off => an ungranted permission loads with a warning; it, too, is
    # advisory under isolation 'none'.
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.setattr(plugins, "_plugins_config",
                        lambda: {"enforce_permissions": False})
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("wp", lambda: "ok", dist=_FakeDist("wp", _manifest_toml(fs_write=True))),
    ]})
    with caplog.at_level(logging.WARNING, logger="maverick.plugins"):
        out = plugins.discover_tools()
    assert [n for n, _ in out] == ["wp"]
    assert "ADVISORY" in caplog.text


def test_no_advisory_for_manifestless_plugin(monkeypatch, caplog):
    # No declared permissions => no grant to qualify => no advisory noise.
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    _set_eps(monkeypatch, {"maverick.tools": [
        _FakeEP("plain", lambda: "ok", dist=_FakeDist("plain-pkg")),  # no manifest
    ]})
    with caplog.at_level(logging.WARNING, logger="maverick.plugins"):
        out = plugins.discover_tools()
    assert [n for n, _ in out] == ["plain"]
    assert "ADVISORY" not in caplog.text


def test_advisory_remains_when_subprocess_proxy_is_selected(monkeypatch, caplog):
    # Subprocess calls do not confine imports, factories or OS access.
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    monkeypatch.setattr(
        plugins, "_plugins_config",
        lambda: {"grant": ["network"], "enforce_permissions": True},
    )
    monkeypatch.setenv("MAVERICK_PLUGIN_ISOLATION", "subprocess")
    entry = _FakeEP("wp", lambda: "ok", dist=_FakeDist("wp", _manifest_toml(network=True)))
    entry.value = "example_plugin:factory"
    _set_eps(monkeypatch, {"maverick.tools": [
        entry,
    ]})
    with caplog.at_level(logging.WARNING, logger="maverick.plugins"):
        out = plugins.discover_tools()
    assert [n for n, _ in out] == ["wp"]
    assert "ADVISORY" in caplog.text


# ---------- pure helpers ----------

def test_permission_violations():
    m = parse_text(_manifest_toml(network=True, subprocess=True))
    assert set(plugins._permission_violations(m, {"network"})) == {"subprocess"}
    assert plugins._permission_violations(m, {"network", "subprocess"}) == []
    assert plugins._permission_violations(None, set()) == []


def test_sensitive_envs_is_a_grantable_permission():
    m = parse_text(_manifest_toml(sensitive_envs=["OPENAI_API_KEY"]))
    assert plugins._permission_violations(m, set()) == ["sensitive_envs"]
    assert plugins._permission_violations(m, {"sensitive_envs"}) == []


def test_find_manifest_reads_from_distribution():
    ep = _FakeEP("x", lambda: None, dist=_FakeDist("xpkg", _manifest_toml(fs_write=True)))
    m = plugins._find_manifest(ep)
    assert m is not None
    assert m.permissions.fs_write is True


def test_find_manifest_none_without_dist_or_file():
    assert plugins._find_manifest(_FakeEP("x", lambda: None)) is None
    assert plugins._find_manifest(_FakeEP("x", lambda: None, dist=_FakeDist("nofile"))) is None


def test_ep_dist_name():
    assert plugins._ep_dist_name(_FakeEP("x", None, dist=_FakeDist("mypkg"))) == "mypkg"
    assert plugins._ep_dist_name(_FakeEP("x", None)) is None
